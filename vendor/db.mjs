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

export async function getUserByLogin(login) {
  const [r] = await pool.query('SELECT * FROM users WHERE login = ? LIMIT 1', [login]);
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

export async function getOrdersByUser(uid) {
  const [r] = await pool.query('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [uid]);
  return r;
}

export async function editOrderByUser(uid, oid, data) {
  await pool.query(
    `UPDATE orders SET product_name = ?, quantity = ?, unit_price = ?, product_link = ?, delivery_date = ?
     WHERE id = ? AND user_id = ? AND status = 'На рассмотрении'`,
    [data.product_name, data.quantity, data.unit_price, data.product_link, data.delivery_date, oid, uid]
  );
}

export async function getActiveOrders() {
  const [r] = await pool.query("SELECT * FROM orders WHERE status <> 'Завершен' ORDER BY created_at DESC");
  return r;
}

export async function getArchiveOrders() {
  const [r] = await pool.query("SELECT * FROM orders WHERE status = 'Завершен' ORDER BY created_at DESC");
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
export async function getAllUsers() {
  const [rows] = await pool.query('SELECT id, name, login, phone, role FROM users ORDER BY id');
  return rows;
}
