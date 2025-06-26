
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
  updateOrderETA,
} from './vendor/db.mjs';

const allowedStatuses = [
  'На рассмотрении',
  'Закупаем',
  'Ждём поставку',
  'Готов к получению',
  'Пауза',
  'Получено',
  'Отменено'
];



dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const hbs = expressHbs.create({
  extname: '.hbs',
  defaultLayout: 'main',
  layoutsDir: path.join(__dirname, 'views', 'layouts'),
  partialsDir: path.join(__dirname, 'views', 'partials'),
  helpers : {
  eq  : (a, b) => a == b,
  date: iso => {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleDateString('ru-RU')        
            .replace(/\./g, '-')                
  }}});

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

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

app.use('/fontawesome', express.static(
  path.join(__dirname, 'node_modules', '@fortawesome', 'fontawesome-free')
));


const isAuth  = (req, _res, next) => req.session.user ? next() : _res.redirect('/login');
const isAdmin = (req, res, next) => req.session.user?.role === 'admin' ? next() : res.status(403).send('Forbidden');


//----------------------------------ЛОГИН--------------------------------
app.get('/', (_req, res) => res.redirect('/login'));
app.get('/login', (_req, res) => res.render('auth/login', { title: 'Вход', isLoginPage: true }));

app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.render('auth/login', { title: 'Вход',isLoginPage: true, error: 'Заполните все поля' });

  const user = await getUserByLogin(login);
  if (!user) return res.render('auth/login', { title: 'Вход', error: 'Пользователь не найден' });
  if (user.password !== password) return res.render('auth/login', { title: 'Вход', error: 'Неверный пароль' });

  req.session.user = { id: user.id, name: user.name, role: user.role };
  res.redirect(user.role === 'admin' ? '/orders/active' : '/orders/my');
});


app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));





// //----------------------------------ПРОФИЛЬ ЮЗЕРА--------------------------------
// app.get('/profile', isAuth, (req, res) =>
//   res.render('profile', { title: 'Мой профиль',isOrdersPage: true, user: req.session.user })
// );
// app.post('/profile/update', isAuth, async (req, res) => {
//   const { name, phone } = req.body;
//   await updateUserProfile(req.session.user.id, name, phone);
//   req.session.user.name = name;
//   res.redirect('/profile');
// });


// res.render('myOrders', {
//   title: 'Мои заказы',
//   orders: await getOrdersByUser(req.session.user.id),
//   filter: req.query.status,
//   isOrdersPage: true        


/* заказы – пользователи */
app.get('/orders/my', isAuth, async (req, res) => {
  const orders = await getOrdersByUser(req.session.user.id);

  res.render('myOrders', {
    title: 'Мои заказы',
    orders,
    filter: req.query.status,
    isOrdersPage: true
  });
});

app.get('/orders/new', isAuth, (_req, res) => res.render('newOrder', { 
  title: 'Новый заказ',
  isOrdersPage: true }));
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
  res.render('activeOrders', { title: 'Активные заказы',isOrdersPage: true, orders: await getActiveOrders() })
);

app.get('/orders/archive', isAuth, isAdmin, async (_req, res) =>
  res.render('archive', { title: 'Архив заказов',isOrdersPage: true, orders: await getArchiveOrders() })
);

app.post('/orders/update-status/:id', isAuth, isAdmin, async (req, res) => {
  const { status } = req.body;

  
  if (!allowedStatuses.includes(status))
    return res.status(400).send('Недопустимый статус');

  await updateOrderStatus(req.params.id, status);
  res.redirect('/orders/active');
});

// админ меняет «Ожидается»
app.post('/orders/update-eta/:id', isAuth, isAdmin, async (req, res) => {
  await updateOrderETA(req.params.id, req.body.delivery_date);
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
