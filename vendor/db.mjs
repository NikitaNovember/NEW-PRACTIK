import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
dotenv.config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  charset: process.env.DB_CHARSET,
  waitForConnections: true,
  connectionLimit: 10
});


export async function getAllUsers(loginFilter = null) {
  let sql = `
    SELECT
      u.id, u.name, u.login, u.role,
      b.reason AS ban_reason,
      b.banned_until AS ban_until
    FROM users u
    LEFT JOIN (
      SELECT b1.*
      FROM user_bans b1
      JOIN (
        SELECT user_id, MAX(id) AS max_id
        FROM user_bans
        WHERE revoked_at IS NULL
          AND (banned_until IS NULL OR banned_until > NOW())
        GROUP BY user_id
      ) last_ban ON last_ban.max_id = b1.id
    ) b ON b.user_id = u.id
  `;

  const params = [];
  if (loginFilter) {
    sql += ' WHERE u.login LIKE ?';
    params.push(`%${loginFilter}%`);
  }

  sql += ' ORDER BY u.id';
  const [rows] = await pool.query(sql, params);
  return rows;
}


export async function updateUserPassword(id, newPassword) {
  await pool.query('UPDATE users SET password = ? WHERE id = ?', [newPassword, id]);
}

// найти пользователя по логину (мы будем хранить email в login)
export async function getUserByLogin(login) {
  const [r] = await pool.query(
    `SELECT id, name, surname, patronymic, phone, role, password
     FROM users WHERE login = ? LIMIT 1`,
    [login]
  );
  return r[0] ?? null;
}

export async function updateUserProfile(id, name, phone) {
  await pool.query('UPDATE users SET name = ?, phone = ? WHERE id = ?', [name, phone, id]);
}

export async function updateOrderETA(id, eta){
  await pool.query('UPDATE orders SET delivery_date = ? WHERE id = ?', [eta, id]);
}

export async function insertOrder(o) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [r] = await conn.query(
      `INSERT INTO orders
        (customer_name, customer_phone, product_name, quantity,
         unit_price, product_link, delivery_date, status, user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'На рассмотрении', ?)`,
      [
        o.customer_name,
        o.customer_phone,
        o.product_name,
        o.quantity,
        o.unit_price,
        o.product_link,
        o.delivery_date,
        o.user_id,
      ]
    );

    const orderId = r.insertId;

    const userComment = (o.user_comment ?? '').toString().trim();
    if (userComment.length) {
      await conn.query(
        `INSERT INTO order_comments (order_id, user_comment, admin_comment)
         VALUES (?, ?, NULL)
         ON DUPLICATE KEY UPDATE user_comment = VALUES(user_comment)`,
        [orderId, userComment.slice(0, 500)]
      );
    }

    await conn.commit();
    return orderId;
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}


export async function getOrdersByUser(uid, status = null) {
  let sql = `
    SELECT o.*,
           c.user_comment,
           c.admin_comment
    FROM orders o
    LEFT JOIN order_comments c ON c.order_id = o.id
    WHERE o.user_id = ?
  `;
  const p = [uid];

  if (status) {
    sql += ' AND o.status = ?';
    p.push(status);
  }

  sql += ' ORDER BY o.created_at DESC';
  const [rows] = await pool.query(sql, p);
  return rows;
}


export async function editOrderByUser(uid, oid, data) {
  await pool.query(
    `UPDATE orders SET product_name = ?, quantity = ?, unit_price = ?, product_link = ?, delivery_date = ?
     WHERE id = ? AND user_id = ? AND status = 'На рассмотрении'`,
    [data.product_name, data.quantity, data.unit_price, data.product_link, data.delivery_date, oid, uid]
  );
}

export async function updateOrderLinkAndDate(oid, uid, link, date) {
  await pool.query(
    `UPDATE orders
       SET product_link  = ?,
           delivery_date = ?
     WHERE id = ? 
       AND user_id = ?
       AND status = 'На рассмотрении'`,
    [link, date, oid, uid]
  );
}


export async function getActiveOrders(loginFilter = null) {
  let sql = `
    SELECT o.*,
           u.login AS user_login,
           c.user_comment,
           c.admin_comment
    FROM orders o
    JOIN users u ON o.user_id = u.id
    LEFT JOIN order_comments c ON c.order_id = o.id
    WHERE o.status NOT IN ('Получено','Отменено')
  `;
  const params = [];

  if (loginFilter) {
    sql += ` AND u.login = ?`;
    params.push(loginFilter);
  }

  sql += ` ORDER BY o.created_at DESC`;
  const [rows] = await pool.query(sql, params);
  return rows;
}



export async function getArchiveOrders() {
  const [rows] = await pool.query(
    `SELECT o.*,
            c.user_comment,
            c.admin_comment
     FROM orders o
     LEFT JOIN order_comments c ON c.order_id = o.id
     WHERE o.status IN ('Получено','Отменено')
     ORDER BY o.created_at DESC`
  );
  return rows;
}

export async function updateOrderStatus(oid, status) {
  await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, oid]);
}
export async function getOrderByIdAndUser(oid, uid) {
  const [r] = await pool.query(
    'SELECT * FROM orders WHERE id = ? AND user_id = ? LIMIT 1',
    [oid, uid]
  );
  return r[0] ?? null;
}


export async function deleteUser(id) {
  await pool.query(
    'DELETE FROM users WHERE id = ?',
    [id]
  );
}

/**
 * Правка админом: ссылка, дата и цена за единицу
 */
export async function updateOrderAdmin(oid, link, date, price) {
  await pool.query(
    `UPDATE orders
       SET product_link  = ?,
           delivery_date = ?,
           unit_price    = ?
     WHERE id = ?`,
    [link, date, price, oid]
  );
}

export async function getUserById(id) {
  const [rows] = await pool.query(
    `SELECT id, name, surname, patronymic, phone, role
     FROM users
     WHERE id = ?
     LIMIT 1`,
    [id]
  );

  return rows[0] ?? null;
}


export async function insertUser(user) {
  const sql = `
    INSERT INTO users
      (name, surname, patronymic, phone, login, email, password, role)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'user')
  `;
  const params = [
    user.name,
    user.surname,
    user.patronymic || null,
    user.phone || null,
    user.login,
    user.email || null,
    user.password // HASH
  ];
  const [result] = await pool.query(sql, params);
  return result.insertId;
}

export async function getActiveBanByUserId(userId) {
  const [rows] = await pool.query(
    `SELECT id, reason, banned_until, created_at
     FROM user_bans
     WHERE user_id = ?
       AND revoked_at IS NULL
       AND (banned_until IS NULL OR banned_until > NOW())
     ORDER BY created_at DESC
     LIMIT 1`,
    [userId]
  );
  return rows[0] ?? null;
}

export async function banUser(userId, adminId, reason, bannedUntil) {
  await pool.query(
    `INSERT INTO user_bans (user_id, admin_id, reason, banned_until)
     VALUES (?, ?, ?, ?)`,
    [userId, adminId, reason, bannedUntil]
  );
}

export async function unbanUser(userId) {
  await pool.query(
    `UPDATE user_bans
     SET revoked_at = NOW()
     WHERE user_id = ?
       AND revoked_at IS NULL`,
    [userId]
  );
}

export async function getArchiveOrdersByUser(uid) {
  const [rows] = await pool.query(
    `SELECT o.*,
            c.user_comment,
            c.admin_comment
     FROM orders o
     LEFT JOIN order_comments c ON c.order_id = o.id
     WHERE o.user_id = ?
       AND o.status IN ('Получено', 'Отменено')
     ORDER BY o.created_at DESC`,
    [uid]
  );
  return rows;
}




export async function insertOAuthUserFromMailru({ email, name, surname }) {
  const sql = `
    INSERT INTO users (name, surname, patronymic, login, email, password, phone, role)
    VALUES (?, ?, NULL, ?, ?, '', NULL, 'user')
  `;

  // login делаем уникальным и читаемым, чтобы не конфликтовал
  const login = `mailru_${email}`;

  const [r] = await pool.query(sql, [name, surname, login, email]);
  return r.insertId;
}


export async function getUserByEmail(email) {
  const [r] = await pool.query(
    `SELECT id, name, surname, patronymic, phone, role, password, email
     FROM users WHERE email = ? LIMIT 1`,
    [email]
  );
  return r[0] ?? null;
}

export async function createDbSession({
  userId,
  selector,
  tokenHash,
  expiresAt,
  ip,
  userAgent
}) {
  await pool.query(
    `INSERT INTO sessions (user_id, selector, token_hash, expires_at, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [userId, selector, tokenHash, expiresAt, ip || null, userAgent || null]
  );
}

export async function getDbSessionBySelector(selector) {
  const [r] = await pool.query(
    `SELECT s.*, u.id AS uid, u.name, u.surname, u.patronymic, u.phone, u.role
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.selector = ? LIMIT 1`,
    [selector]
  );
  return r[0] ?? null;
}

export async function revokeDbSession(selector) {
  await pool.query(
    `UPDATE sessions SET revoked_at = NOW() WHERE selector = ?`,
    [selector]
  );
}

export async function cleanupExpiredSessions() {
  await pool.query(
    `DELETE FROM sessions WHERE expires_at < NOW() OR revoked_at IS NOT NULL`
  );
}




export async function updateOrderAdminAction(oid, status, adminComment) {
  const safeStatus = String(status || '').trim();

  const raw = (adminComment ?? '').toString().trim();
  const safeComment = raw.length ? raw.slice(0, 500) : null;

  // 1) сохранить/обновить комментарий админа
  await pool.query(
    `INSERT INTO order_comments (order_id, admin_comment)
     VALUES (?, ?)
     ON DUPLICATE KEY UPDATE admin_comment = VALUES(admin_comment)`,
    [oid, safeComment]
  );

  // 2) обновить статус заказа
  await pool.query(
    `UPDATE orders SET status = ? WHERE id = ?`,
    [safeStatus, oid]
  );
}


