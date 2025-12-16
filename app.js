import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import fileUpload from 'express-fileupload';
import path from 'path';
import { fileURLToPath } from 'url';
import expressHbs from 'express-handlebars';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import axios from 'axios';
import crypto from 'crypto';

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
  updateUserPassword,
  deleteUser,
  updateOrderAdmin,
  insertUser,
  getUserById,
  getActiveBanByUserId,
  banUser,
  unbanUser,
  getArchiveOrdersByUser,
  getUserByEmail,

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

const SALT_ROUNDS = 10;

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
    multiply: (a, b) => (Number(a) * Number(b)).toFixed(2),
    truncate: (str, len) => {
      if (typeof str !== 'string') return '';
      return str.length > len
        ? str.slice(0, len) + '…'
        : str;
    }
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

app.use(async (req, res, next) => {
  if (!req.session.user && req.cookies.user_id) {
    const user = await getUserById(req.cookies.user_id);

    if (user) {
      req.session.user = user;
    }
  }
  next();
});


app.use((req, res, next) => {
  res.locals.session = req.session;
  res.locals.cookies = req.cookies;
  next();
});



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
  if (!user) return res.render('auth/login', { title: 'Вход', isLoginPage: true, error: 'Пользователь не найден' });
  if (user.password !== password) return res.render('auth/login', { title: 'Вход', isLoginPage: true, error: 'Неверный пароль' });

  const ban = await getActiveBanByUserId(user.id);
if (ban) {
  const untilText = ban.banned_until
    ? `до ${new Date(ban.banned_until).toLocaleString('ru-RU')}`
    : 'навсегда';

  return res.render('auth/login', {
    title: 'Вход',
    isLoginPage: true,
    error: `Аккаунт заблокирован ${untilText}. Причина: ${ban.reason}`
  });
}

  req.session.user = {
  id: user.id,
  name: user.name,
  surname: user.surname,
  patronymic: user.patronymic,
  phone: user.phone,
  role: user.role
};



// === COOKIE ===
res.cookie('user_id', user.id, {
  httpOnly: true,
  maxAge: 1000 * 60 * 60 * 24 // 1 день
});

res.cookie('user_role', user.role, {
  httpOnly: true,
  maxAge: 1000 * 60 * 60 * 24
});

  res.redirect(user.role === 'admin' ? '/orders/active' : '/orders/my');
});


app.get('/logout', (req, res) => {
  res.clearCookie('user_id');
  res.clearCookie('user_role');

  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// ===== РЕГИСТРАЦИЯ =====
app.get('/register', (_req, res) => {
  res.render('auth/register', { title: 'Регистрация', isLoginPage: true });
});

app.post('/register', async (req, res) => {
  const rxName  = /^[А-Яа-яЁё\s\-]{2,50}$/;
  const rxLogin = /^[a-zA-Z0-9_]{3,20}$/;
  const rxPhone = /^\+7\d{10}$/;
  const rxEmail = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  const {
    name,
    surname,
    patronymic,
    phone,
    login,
    email,
    password,
    password2
  } = req.body;

  // 1) базовая проверка обязательных полей
  if (!name || !surname || !login || !password || !password2) {
    return res.render('auth/register', {
      title: 'Регистрация',
      isLoginPage: true,
      error: 'Заполните обязательные поля'
    });
  }

  // 2) ФИО
  if (!rxName.test(name) || !rxName.test(surname) || (patronymic && !rxName.test(patronymic))) {
    return res.render('auth/register', {
      title: 'Регистрация',
      isLoginPage: true,
      error: 'ФИО: только русские буквы, пробел и дефис'
    });
  }

  // 3) телефон (у тебя он может быть NULL)
  if (phone && !rxPhone.test(phone)) {
    return res.render('auth/register', {
      title: 'Регистрация',
      isLoginPage: true,
      error: 'Телефон: формат +7XXXXXXXXXX'
    });
  }

  // 4) логин
  if (!rxLogin.test(login)) {
    return res.render('auth/register', {
      title: 'Регистрация',
      isLoginPage: true,
      error: 'Логин: 3–20 символов (латиница, цифры, _)'
    });
  }

  // 5) пароль
  if (password.length < 4 || password.length > 50) {
    return res.render('auth/register', {
      title: 'Регистрация',
      isLoginPage: true,
      error: 'Пароль: 4–50 символов'
    });
  }

  if (password !== password2) {
    return res.render('auth/register', {
      title: 'Регистрация',
      isLoginPage: true,
      error: 'Пароли не совпадают'
    });
  }

  // 6) проверка уникальности логина
  const exists = await getUserByLogin(login);
  if (exists) {
    return res.render('auth/register', {
      title: 'Регистрация',
      isLoginPage: true,
      error: 'Логин уже занят'
    });
  }

  if (!email || !rxEmail.test(email) || email.length > 255) {
  return res.render('auth/register', {
    title: 'Регистрация',
    isLoginPage: true,
    error: 'Email указан неверно'
  });
}

const emailExists = await getUserByEmail(email);
if (emailExists) {
  return res.render('auth/register', {
    title: 'Регистрация',
    isLoginPage: true,
    error: 'Email уже используется'
  });
}


  // 7) хэширование
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  // 8) запись в БД
  const userId = await insertUser({
    name,
    surname,
    patronymic,
    phone,
    login,
    email,
    password: passwordHash
  });

  // 9) автологин: session + cookie
  req.session.user = {
    id: userId,
    name,
    surname,
    patronymic,
    phone,
    role: 'user'


  };

  res.cookie('user_id', userId, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 });
  res.cookie('user_role', 'user', { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 });

  return res.redirect('/orders/my');
});


app.get('/register', (_req, res) => {
  res.render('auth/register', { title: 'Регистрация', isLoginPage: true });
});



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

app.get('/orders/my-archive', isAuth, async (req, res) => {
  const orders = await getArchiveOrdersByUser(req.session.user.id);

  res.render('myArchive', {
    title: 'Архив заказов',
    isOrdersPage: true,
    orders
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
  const {
    customer_name,
    customer_phone,
    product_name,
    quantity,
    unit_price,
    product_link,
    delivery_date
  } = req.body;

  if (!product_name || product_name.length < 1 || product_name.length > 255) {
    return res.status(400).send('Название товара: от 1 до 255 символов');
  }
  
  const qty = Number(quantity);
  if (!Number.isInteger(qty) || qty < 1 || qty > 10000) {
    return res.status(400).send('Количество: целое число от 1 до 10000');
  }

  if (product_link && product_link.length > 32767) {
    return res.status(400).send('Ссылка на товар: не более 32767 символов');
  }

  const price = Number(unit_price);
  if (isNaN(price) || price < 1 || price > 100_000_000) {
    return res.status(400).send('Цена: от 1 до 100 000 000');
  }

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

app.get('/orders/update-status/:id', isAuth, isAdmin, (req, res) => {
  res.redirect('/orders/active');
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

app.get('/admin/users', isAuth, isAdmin, async (req, res) => {
  const loginFilter = req.query.login?.trim() || null;
  const users = await getAllUsers(loginFilter);
  res.render('adminUsers', {
    title: 'БД пользователей',
    users,
    loginFilter,
    isOrdersPage: true
  });
});

// Изменить пароль
app.post('/admin/users/:id/password', isAuth, isAdmin, async (req, res) => {
  const { password } = req.body;
  await updateUserPassword(req.params.id, password);
  res.redirect('/admin/users');
});

// Удалить пользователя
app.post('/admin/users/:id/delete', isAuth, isAdmin, async (req, res) => {
  await deleteUser(req.params.id);
  res.redirect('/admin/users');
});

app.post('/orders/update-admin/:id', isAuth, isAdmin, async (req, res) => {
  const { product_link, delivery_date, unit_price } = req.body;
  const todayTs = new Date().setHours(0,0,0,0);
  if (new Date(delivery_date).getTime() < todayTs) {
    return res.status(400).send('Дата доставки не может быть в прошлом');
  }
  if (Number(unit_price) < 0) {
    return res.status(400).send('Цена не может быть отрицательной');
  }

  await updateOrderAdmin (
    req.params.id,
    product_link,
    delivery_date,
    unit_price
  );
  res.redirect('/orders/active');
});

app.post('/admin/users/:id/ban', isAuth, isAdmin, async (req, res) => {
  const userId = Number(req.params.id);
  const adminId = req.session.user.id;

  const reason = (req.body.reason || '').trim();
  const duration = (req.body.duration || 'permanent').trim(); // permanent | 1 | 7 | 30 ...

  if (!reason || reason.length > 500) {
    return res.status(400).send('Причина бана: 1–500 символов');
  }

  let bannedUntil = null;
  if (duration !== 'permanent') {
    const days = Number(duration);
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      return res.status(400).send('Некорректный срок бана');
    }
    const d = new Date();
    d.setDate(d.getDate() + days);
    bannedUntil = d;
  }

  await banUser(userId, adminId, reason, bannedUntil);
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/unban', isAuth, isAdmin, async (req, res) => {
  await unbanUser(req.params.id);
  res.redirect('/admin/users');
});

// ===== Mail.ru OAuth =====
app.get('/auth/mailru', (req, res) => {
  console.log('MAILRU_REDIRECT_URI:', process.env.MAILRU_REDIRECT_URI);
  const state = crypto.randomBytes(16).toString('hex');
  req.session.mailru_oauth_state = state;

  const redirectUri = process.env.MAILRU_REDIRECT_URI;
  const clientId = process.env.MAILRU_CLIENT_ID;

  const url =
    `https://o2.mail.ru/login` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent('userinfo')}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(url);
});

app.get('/auth/mailru/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) return res.redirect('/login');

    // проверяем state (защита от CSRF)
    if (!state || state !== req.session.mailru_oauth_state) {
      return res.status(400).send('Bad state');
    }
    req.session.mailru_oauth_state = null;

    if (!code) return res.status(400).send('No code');

    // 1) меняем code на access_token
    const tokenResp = await axios.post(
  'https://o2.mail.ru/token',
  new URLSearchParams({
    grant_type: 'authorization_code',
    code: String(code),
    redirect_uri: process.env.MAILRU_REDIRECT_URI,
    client_id: process.env.MAILRU_CLIENT_ID,
    client_secret: process.env.MAILRU_CLIENT_SECRET,
  }).toString(),
  {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }
);


    const accessToken = tokenResp.data?.access_token;
    console.log('MAILRU TOKEN RESP:', tokenResp.data);
    if (!accessToken) return res.status(400).send('No access_token');

    const userInfoResp = await axios.get('https://o2.mail.ru/userinfo', {
    params: {
      access_token: accessToken,
      client_id: process.env.MAILRU_CLIENT_ID,
    },
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
    timeout: 10000,
    validateStatus: () => true,
  });

  console.log('MAILRU USERINFO STATUS:', userInfoResp.status);
  console.log('MAILRU USERINFO DATA:', userInfoResp.data);

  if (userInfoResp.status !== 200) {
    return res.redirect('/login?error=mailru_userinfo_failed');
  }

  const info = userInfoResp.data || {};


    const email = info.email;
    if (!email) return res.status(400).send('Mail.ru не вернул email');

    // ✅ ИЩЕМ ПО EMAIL
    let user = await getUserByEmail(email);

    // ✅ ЕСЛИ НЕТ — СОЗДАЁМ
    if (!user) {
      const fullName = String(info.name || '').trim();
      const firstName = String(info.first_name || '').trim();
      const lastName = String(info.last_name || '').trim();

      const name =
        firstName ||
        (fullName.split(' ')[1] || fullName.split(' ')[0] || 'Пользователь');

      const surname =
        lastName ||
        (fullName.split(' ')[0] || 'MailRu');

      await insertOAuthUserFromMailru({
        email,
        name,
        surname
      });

      // получаем созданного пользователя
      user = await getUserByEmail(email);
    }

    // 5) логиним в твою сессию как обычно
    req.session.user = {
      id: user.id,
      name: user.name,
      surname: user.surname,
      patronymic: user.patronymic,
      phone: user.phone,
      role: user.role,
    };

    // 6) редирект по роли
    return res.redirect(user.role === 'admin' ? '/orders/active' : '/orders/my');
  } catch (e) {
    console.error(e);
    return res.redirect('/login');
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`http://localhost:${PORT}`));

/*
PORT=3000
DB_PORT=3407
DB_HOST=platon.teyhd.ru
DB_USER=student
DB_PASS=studpass
DB_NAME=Nikita_todo
DB_CHARSET=utf8mb4_0900_ai_ci

MAILRU_CLIENT_ID=019b28b8cc9973a9b641f63f0e12491f
MAILRU_CLIENT_SECRET=019b28b8cc9973b4952bf827e9bdff58
MAILRU_REDIRECT_URI=http://localhost:3000/auth/mailru/callback
*/