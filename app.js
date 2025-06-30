
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
  getOrderByIdAndUser,
  updateOrderLinkAndDate,        
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

  /* ——— helpers ——— */
  helpers: {
    /* сравнение */
      /* eq как inline-функция И блок-helper */
    eq: function (a, b, options) {
    /* если options (3-й аргумент) отсутствует → вызов inline */
      if (arguments.length < 3) return a == b;

    /* вызов как блок */
      return (a == b) ? options.fn(this) : options.inverse(this);
  },

    /* dd-mm-yyyy */
    date: iso => {
      if (!iso) return '—';
      const d = new Date(iso);
      return d.toLocaleDateString('ru-RU').replace(/\./g, '-');
    },

    /* цена × количество → 2 знака после запятой */
    multiply: (a, b) => (Number(a) * Number(b)).toFixed(2)
  }
});

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


//-ЛОГИН
app.get('/', (_req, res) => res.redirect('/login'));
app.get('/login', (_req, res) => res.render('auth/login', { title: 'Вход', isLoginPage: true }));

app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.render('auth/login', { title: 'Вход',isLoginPage: true, error: 'Заполните все поля' });

  const user = await getUserByLogin(login);
  if (!user) return res.render('auth/login', { title: 'Вход', error: 'Пользователь не найден' });
  if (user.password !== password) return res.render('auth/login', { title: 'Вход', error: 'Неверный пароль' });

  req.session.user = { id: user.id, name: user.name, surname: user.surname, patronymic: user.patronymic, phone: user.phone,  role: user.role };
  res.redirect(user.role === 'admin' ? '/orders/active' : '/orders/my');
});


app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));




app.get('/orders/my', isAuth, async (req, res) => {
  const filter = req.query.status || '';          // '' = «Все заказы»
    let orders = await getOrdersByUser(
    req.session.user.id,
    filter ? filter : null
  );

  /* по умолчанию скрываем «Отменено» и «Получено» */
  if (!filter) {
    orders = orders.filter(o =>
      o.status !== 'Отменено' && o.status !== 'Получено'
    );
  }

  res.render('myOrders', {
    title: 'Мои заказы',
    orders,
    filter,
    isOrdersPage: true
  });
});

app.get('/orders/new', isAuth, (_req, res) => {
  const today = new Date().toISOString().slice(0, 10);   // YYYY-MM-DD
  const fullName = `${_req.session.user.surname} ${_req.session.user.name} ${_req.session.user.patronymic}`.trim();
  res.render('newOrder', { 
  title: 'Новый заказ',
  isOrdersPage: true,
  today,
  fullName,
  userPhone: _req.session.user.phone  
    });
  });

app.post('/orders/new', isAuth, async (req, res) => {
  const rxFio = /^[А-Яа-яЁё\s\-]{5,60}$/;
  const rxPhone = /^\+7\d{10}$/;

  if (!rxFio.test(req.body.customer_name)) {
    return res.status(400).send('ФИО должно содержать только русские буквы, пробелы и дефис.');
  }

  if (!rxPhone.test(req.body.customer_phone)) {
  return res.status(400).send('Телефон: только цифры, 10-15 символов.');
  }

  await insertOrder({ ...req.body, user_id: req.session.user.id });
  res.redirect('/orders/my');
});

app.post('/orders/edit/:id', isAuth, async (req, res) => {
  await editOrderByUser(req.session.user.id, req.params.id, req.body);
  res.redirect('/orders/my');
});

/* пользователь отменяет свой заказ, если тот ещё "На рассмотрении" */
app.post('/orders/cancel/:id', isAuth, async (req, res) => {
  const order = await getOrderByIdAndUser(req.params.id, req.session.user.id);

  /* если заказа нет или его уже начали обрабатывать – просто назад */
  if (!order || order.status !== 'На рассмотрении')
    return res.redirect('/orders/my');

  await updateOrderStatus(req.params.id, 'Отменено');
  res.redirect('/orders/my');
});

app.post('/orders/update-user/:id', isAuth, async (req, res) => {
  const { product_link, delivery_date } = req.body;
  await updateOrderLinkAndDate(
    req.params.id,
    req.session.user.id,
    product_link,
    delivery_date
  );
  res.redirect('/orders/my');
});


// app.js
app.get('/orders/active', isAuth, isAdmin, async (req, res) => {
  const loginFilter = req.query.login?.trim() || null;
  const orders = await getActiveOrders(loginFilter);
  res.render('activeOrders', {
    title: 'Активные заказы',
    isOrdersPage: true,
    orders,
    loginFilter
  });
});


app.get('/orders/archive', isAuth, isAdmin, async (_req, res) =>
  res.render('archive', { title: 'Архив заказов',isOrdersPage: true, orders: await getArchiveOrders() })
);

app.post('/orders/update-status/:id', isAuth, isAdmin, async (req, res) => {
  const { status } = req.body;

  const allowed = [
    'На рассмотрении','Закупаем','Ждём поставку',
    'Готов к получению','Пауза','Получено','Отменено'
  ];
  if (!allowed.includes(status))
    return res.status(400).send('Bad status');

  await updateOrderStatus(req.params.id, status);

  // /* === ключ: отправляем на нужную страницу === */
  // if (status === 'Получено' || status === 'Отменено') {
  //   return res.redirect('/orders/archive');
  // }
  res.redirect('/orders/active');
});

app.post('/orders/update-eta/:id', isAuth, isAdmin, async (req, res) => {
  await updateOrderETA(req.params.id, req.body.delivery_date);
  res.redirect('/orders/active');
});

app.get('/orders/edit/:id', isAuth, async (req, res) => {
  const order = await getOrderByIdAndUser(req.params.id, req.session.user.id);

  
  if (!order || order.status !== 'На рассмотрении')
    return res.redirect('/orders/my');

  res.render('editOrder', { title: 'Редактировать заказ', order });
});

app.get('/admin/users', isAuth, isAdmin, async (_req, res) => {
  res.render('adminUsers', { title: 'БД пользователей',isOrdersPage: true, users: await getAllUsers() });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`http://localhost:${PORT}`));

// 