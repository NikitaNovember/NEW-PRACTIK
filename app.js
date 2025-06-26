// импорт прежний, без bcrypt
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import fileUpload from 'express-fileupload';
import path from 'path';
import { fileURLToPath } from 'url';
import expressHbs from 'express-handlebars';
import dotenv from 'dotenv';
import {
  getUserByLogin,
  updateUserProfile,
  insertOrder,
  getOrdersByUser,
  editOrderByUser,
  getActiveOrders,
  getArchiveOrders,
  updateOrderStatus,
  getAllUsers,
} from './vendor/db.mjs';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const hbs = expressHbs.create({
  extname: '.hbs',
  defaultLayout: 'main',
  layoutsDir: path.join(__dirname, 'views', 'layouts'),
  partialsDir: path.join(__dirname, 'views', 'partials'),
  helpers: { eq: (a, b) => a == b }
});

const app = express();
app.engine('.hbs', hbs.engine);
app.set('view engine', '.hbs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(fileUpload());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false
}));
app.use(express.static(path.join(__dirname, 'public')));

const isAuth  = (req, _res, next) => req.session.user ? next() : _res.redirect('/login');
const isAdmin = (req, res, next) => req.session.user?.role === 'admin' ? next() : res.status(403).send('Forbidden');

app.get('/', (_req, res) => res.redirect('/login'));
app.get('/login', (_req, res) => res.render('auth/login', { title: 'Вход' }));

app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.render('auth/login', { title: 'Вход', error: 'Заполните все поля' });

  const user = await getUserByLogin(login);
  if (!user) return res.render('auth/login', { title: 'Вход', error: 'Пользователь не найден' });
  if (user.password !== password) return res.render('auth/login', { title: 'Вход', error: 'Неверный пароль' });

  req.session.user = { id: user.id, name: user.name, role: user.role };
  res.redirect(user.role === 'admin' ? '/orders/active' : '/orders/my');
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

/* профиль */
app.get('/profile', isAuth, (req, res) =>
  res.render('profile', { title: 'Мой профиль', user: req.session.user })
);
app.post('/profile/update', isAuth, async (req, res) => {
  const { name, phone } = req.body;
  await updateUserProfile(req.session.user.id, name, phone);
  req.session.user.name = name;
  res.redirect('/profile');
});

/* заказы – пользователи */
app.get('/orders/my', isAuth, async (req, res) =>
  res.render('myOrders', { title: 'Мои заказы', orders: await getOrdersByUser(req.session.user.id) })
);

app.get('/orders/new', isAuth, (_req, res) => res.render('newOrder', { title: 'Новый заказ' }));
app.post('/orders/new', isAuth, async (req, res) => {
  await insertOrder({ ...req.body, user_id: req.session.user.id });
  res.redirect('/orders/my');
});

app.post('/orders/edit/:id', isAuth, async (req, res) => {
  await editOrderByUser(req.session.user.id, req.params.id, req.body);
  res.redirect('/orders/my');
});

/* заказы – админ */
app.get('/orders/active', isAuth, isAdmin, async (_req, res) =>
  res.render('activeOrders', { title: 'Активные заказы', orders: await getActiveOrders() })
);

app.get('/orders/archive', isAuth, isAdmin, async (_req, res) =>
  res.render('archive', { title: 'Архив заказов', orders: await getArchiveOrders() })
);

app.post('/orders/update-status/:id', isAuth, isAdmin, async (req, res) => {
  await updateOrderStatus(req.params.id, req.body.status);
  res.redirect('/orders/active');
});
app.get('/orders/edit/:id', isAuth, async (req, res) => {
  const order = await getOrderByIdAndUser(req.params.id, req.session.user.id);

  // если заказ не найден или уже не «На рассмотрении» — обратно к списку
  if (!order || order.status !== 'На рассмотрении')
    return res.redirect('/orders/my');

  res.render('editOrder', { title: 'Редактировать заказ', order });
});

app.get('/admin/users', isAuth, isAdmin, async (_req, res) => {
  res.render('adminUsers', { title: 'БД пользователей', users: await getAllUsers() });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
