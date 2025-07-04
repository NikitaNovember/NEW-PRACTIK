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
  let sql = 'SELECT id, name, login, role FROM users';
  const params = [];
  if (loginFilter) {
    sql += ' WHERE login LIKE ?';
    params.push(`%${loginFilter}%`);
  }
  sql += ' ORDER BY id';
  const [rows] = await pool.query(sql, params);
  return rows;
}

export async function updateUserPassword(id, newPassword) {
  await pool.query('UPDATE users SET password = ? WHERE id = ?', [newPassword, id]);
}

export async function getUserByLogin(login) {
    const [r] = await pool.query(
      `SELECT id, name, surname, patronymic, phone, role, password
      FROM users WHERE login = ? LIMIT 1`, [login]);
  return r[0] ?? null;
}

export async function updateUserProfile(id, name, phone) {
  await pool.query('UPDATE users SET name = ?, phone = ? WHERE id = ?', [name, phone, id]);
}

export async function updateOrderETA(id, eta){
  await pool.query('UPDATE orders SET delivery_date = ? WHERE id = ?', [eta, id]);
}

export async function insertOrder(o) {
  const sql = `
    INSERT INTO orders
    (customer_name, customer_phone, product_name, quantity,
     unit_price, product_link, delivery_date, status, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'На рассмотрении', ?)
  `;
  const p = [o.customer_name, o.customer_phone, o.product_name, o.quantity,
             o.unit_price, o.product_link, o.delivery_date, o.user_id];
  const [r] = await pool.query(sql, p);
  return r.insertId;
}

export async function getOrdersByUser(uid, status = null) {
  let  sql = 'SELECT * FROM orders WHERE user_id = ?';
  const p  = [uid];

  if (status) {                  // если нужна фильтрация
    sql += ' AND status = ?';
    p.push(status);
  }

  sql += ' ORDER BY created_at DESC';
  const [r] = await pool.query(sql, p);
  return r;
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


// vendor/db.mjs
export async function getActiveOrders(loginFilter = null) {
  // если передан loginFilter, добавляем условие по users.login
  let sql = `
    SELECT o.*, u.login AS user_login
    FROM orders o
    JOIN users u ON o.user_id = u.id
    WHERE o.status NOT IN ('Получено','Отменено')
  `;
  const params = [];

  if (loginFilter) {
    sql += ` AND u.login = ?`;
    params.push(loginFilter);
  }

  sql += ` ORDER BY o.created_at DESC`;
  const [r] = await pool.query(sql, params);
  return r;
}


export async function getArchiveOrders() {
  const [r] = await pool.query(
    "SELECT * FROM orders \
     WHERE status IN ('Получено','Отменено') \
     ORDER BY created_at DESC"
  );
  return r;
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
