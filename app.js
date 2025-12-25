// app.js (полностью)
// ВАЖНО: в ./vendor/db.mjs должны быть функции, которые тут импортируются.
// Если какой-то функции нет — добавь/экспортируй её в db.mjs (я специально все использованные импорты собрала в одном месте).

import express from 'express';
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
	// users
	getUserByLogin,
	getUserByEmail,
	insertUser,

	// orders
	insertOrder,
	getOrdersByUser,
	editOrderByUser,
	getOrderByIdAndUser,
	updateOrderLinkAndDate,
	getActiveOrders,
	getArchiveOrders,
	getArchiveOrdersByUser,
	updateOrderStatus,
	updateOrderETA,
	updateOrderAdmin,
	updateOrderAdminAction,

	// admin users
	getAllUsers,
	updateUserPassword,
	deleteUser,

	// bans
	getActiveBanByUserId,
	banUser,
	unbanUser,

	// db sessions
	createDbSession,
	getDbSessionBySelector,
	revokeDbSession,

	// oauth mailru
	insertOAuthUserFromMailru,
} from './vendor/db.mjs';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SALT_ROUNDS = 10;

const allowedStatuses = [
	'На рассмотрении',
	'Закупаем',
	'Ждём поставку',
	'Готов к получению',
	'Пауза',
	'Получено',
	'Отменено',
];

const isProd = process.env.NODE_ENV === 'production';

function makeSessionToken() {
	const selector = crypto.randomBytes(16).toString('hex'); // 32 chars
	const validator = crypto.randomBytes(32).toString('base64url'); // удобно для cookie
	return { selector, validator, cookieValue: `${selector}.${validator}` };
}

function authCookieOptions(maxAgeMs) {
	return {
		httpOnly: true,
		sameSite: 'lax',
		secure: isProd, // в prod лучше true (https)
		maxAge: maxAgeMs,
	};
}

async function logoutByCookie(req, res) {
  const raw = req.cookies?.auth_token;
  if (raw) {
    const [selector] = String(raw).split('.');
    if (selector) {
      try { await revokeDbSession(selector); } catch {}
    }
  }

  res.clearCookie('auth_token', {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  });
}

// ---------- Handlebars ----------
const hbs = expressHbs.create({
	extname: '.hbs',
	defaultLayout: 'main',
	layoutsDir: path.join(__dirname, 'views', 'layouts'),
	partialsDir: path.join(__dirname, 'views', 'partials'),
	helpers: {
		eq: function (a, b, options) {
			if (arguments.length < 3) return a == b;
			return a == b ? options.fn(this) : options.inverse(this);
		},
		date: (iso) => {
			if (!iso) return '—';
			const d = new Date(iso);
			return d.toLocaleDateString('ru-RU').replace(/\./g, '-');
		},
		multiply: (a, b) => (Number(a) * Number(b)).toFixed(2),
		truncate: (str, len) => {
			if (typeof str !== 'string') return '';
			return str.length > len ? str.slice(0, len) + '…' : str;
		},
	},
});

// ---------- App ----------
const app = express();

app.use(express.static(path.join(__dirname, 'public')));
app.engine('.hbs', hbs.engine);
app.set('view engine', '.hbs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(fileUpload());

app.use('/fontawesome', express.static(path.join(__dirname, 'node_modules', '@fortawesome', 'fontawesome-free')));

// ---------- DB-token auth (мягкий) ----------
// Выставляет req.user если токен валиден. Если токен битый — чистит cookie.
// НЕ редиректит сам, чтобы можно было показывать login/register спокойно.
async function authByDbTokenSoft(req, res, next) {
	try {
		req.user = null;

		const raw = req.cookies?.auth_token;
		if (!raw) return next();

		const parts = String(raw).split('.');
		if (parts.length !== 2) {
			res.clearCookie('auth_token');
			return next();
		}

		const [selector, validator] = parts;
		if (!selector || !validator) {
			res.clearCookie('auth_token');
			return next();
		}

		const sess = await getDbSessionBySelector(selector);
		if (!sess) {
			res.clearCookie('auth_token');
			return next();
		}

		if (sess.revoked_at) {
			res.clearCookie('auth_token');
			return next();
		}

		if (!sess.expires_at || new Date(sess.expires_at) < new Date()) {
			try {
				await revokeDbSession(selector);
			} catch {}
			res.clearCookie('auth_token');
			return next();
		}

		const ok = await bcrypt.compare(validator, sess.token_hash);
		if (!ok) {
			try {
				await revokeDbSession(selector);
			} catch {}
			res.clearCookie('auth_token');
			return next();
		}

		req.user = {
			id: sess.uid,
			role: sess.role,
			name: sess.name,
			surname: sess.surname,
			patronymic: sess.patronymic,
			phone: sess.phone,
			email: sess.email,
		};

		return next();
	} catch (e) {
		console.error('authByDbTokenSoft error:', e);
		res.clearCookie('auth_token');
		return next();
	}
}

app.use(authByDbTokenSoft);

// Чтобы в шаблонах было доступно {{user}} и {{session.user}} (если ты где-то это используешь)
app.use((req, res, next) => {
	res.locals.user = req.user;
	res.locals.cookies = req.cookies;
	// совместимость с твоими шаблонами (где было session.user)
	res.locals.session = { user: req.user };
	next();
});

function requireAuth(req, res, next) {
	if (req.user) return next();
	return res.redirect('/login');
}

function requireAdmin(req, res, next) {
	if (req.user?.role === 'admin') return next();
	return res.status(403).send('Forbidden');
}

// ---------- routes ----------

// home -> login
app.get('/', (_req, res) => res.redirect('/login'));

// login page
app.get('/login', (req, res) => {
	if (req.user) {
		return res.render('auth/login', {
			title: 'Вход',
			isLoginPage: true,
			info: 'Вы уже авторизованы. Перейдите к заказам.',
		});
	}
	return res.render('auth/login', { title: 'Вход', isLoginPage: true });
});

// login submit (bcrypt + db session)
app.post('/login', async (req, res) => {
	const { login, password } = req.body;

	if (!login || !password) {
		return res.render('auth/login', { title: 'Вход', isLoginPage: true, error: 'Заполните все поля' });
	}

	const user = await getUserByLogin(login);
	if (!user) {
		return res.render('auth/login', { title: 'Вход', isLoginPage: true, error: 'Пользователь не найден' });
	}

	const passOk = await bcrypt.compare(password, user.password);
	if (!passOk) {
		return res.render('auth/login', { title: 'Вход', isLoginPage: true, error: 'Неверный пароль' });
	}

	const ban = await getActiveBanByUserId(user.id);
	if (ban) {
		const untilText = ban.banned_until ? `до ${new Date(ban.banned_until).toLocaleString('ru-RU')}` : 'навсегда';
		return res.render('auth/login', {
			title: 'Вход',
			isLoginPage: true,
			error: `Аккаунт заблокирован ${untilText}. Причина: ${ban.reason}`,
		});
	}

	const { selector, validator, cookieValue } = makeSessionToken();
	const tokenHash = await bcrypt.hash(validator, SALT_ROUNDS);

	const expiresAt = new Date();
	expiresAt.setDate(expiresAt.getDate() + 1);

	await createDbSession({
		userId: user.id,
		selector,
		tokenHash,
		expiresAt,
		ip: req.ip,
		userAgent: req.get('user-agent') || null,
	});

	res.cookie('auth_token', cookieValue, authCookieOptions(1000 * 60 * 60 * 24));

	return res.redirect(user.role === 'admin' ? '/orders/active' : '/orders/my');
});

app.get('/logout', async (req, res) => {
  await logoutByCookie(req, res);
  return res.redirect('/login');
});



// ---------- register ----------
app.get('/register', async (req, res) => {
  await logoutByCookie(req, res);
  return res.render('auth/register', { title: 'Регистрация', isLoginPage: true });
});


app.post('/register', async (req, res) => {
	const rxName = /^[А-Яа-яЁё\s\-]{2,50}$/;
	const rxLogin = /^[a-zA-Z0-9_]{3,20}$/;
	const rxPhone = /^\+7\d{10}$/;
	const rxEmail = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

	const { name, surname, patronymic, phone, login, email, password, password2 } = req.body;

	if (!name || !surname || !login || !email || !password || !password2) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'Заполните обязательные поля' });
	}

	if (!rxName.test(name) || !rxName.test(surname) || (patronymic && !rxName.test(patronymic))) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'ФИО: русские буквы, пробел и дефис' });
	}

	if (phone && !rxPhone.test(phone)) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'Телефон: формат +7XXXXXXXXXX' });
	}

	if (!rxLogin.test(login)) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'Логин: 3–20 (латиница, цифры, _)' });
	}

	if (!rxEmail.test(email) || email.length > 255) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'Email указан неверно' });
	}

	if (password.length < 4 || password.length > 50) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'Пароль: 4–50 символов' });
	}

	if (password !== password2) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'Пароли не совпадают' });
	}

	const loginExists = await getUserByLogin(login);
	if (loginExists) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'Логин уже занят' });
	}

	const emailExists = await getUserByEmail(email);
	if (emailExists) {
		return res.render('auth/register', { title: 'Регистрация', isLoginPage: true, error: 'Email уже используется' });
	}

	const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

	const userId = await insertUser({
		name,
		surname,
		patronymic: patronymic || null,
		phone: phone || null,
		login,
		email,
		password: passwordHash,
	});

	// авто-логин через DB-сессию
	const { selector, validator, cookieValue } = makeSessionToken();
	const tokenHash = await bcrypt.hash(validator, SALT_ROUNDS);

	const expiresAt = new Date();
	expiresAt.setDate(expiresAt.getDate() + 1);

	await createDbSession({
		userId,
		selector,
		tokenHash,
		expiresAt,
		ip: req.ip,
		userAgent: req.get('user-agent') || null,
	});

	res.cookie('auth_token', cookieValue, authCookieOptions(1000 * 60 * 60 * 24));

	return res.redirect('/orders/my');
});



// ---------- orders: user ----------
app.get('/orders/my', requireAuth, async (req, res) => {
	const filter = req.query.status || '';
	let orders = await getOrdersByUser(req.user.id, filter ? filter : null);

	if (!filter) {
		orders = orders.filter((o) => o.status !== 'Отменено' && o.status !== 'Получено');
	}

	return res.render('myOrders', {
		title: 'Мои заказы',
		orders,
		filter,
		isOrdersPage: true,
	});
});

app.get('/orders/my-archive', requireAuth, async (req, res) => {
	const orders = await getArchiveOrdersByUser(req.user.id);
	return res.render('myArchive', {
		title: 'Архив заказов',
		isOrdersPage: true,
		orders,
	});
});

app.get('/orders/new', requireAuth, (_req, res) => {
	const today = new Date().toISOString().slice(0, 10);
	const fullName = `${_req.user.surname} ${_req.user.name} ${_req.user.patronymic || ''}`.trim();

	return res.render('newOrder', {
		title: 'Новый заказ',
		isOrdersPage: true,
		today,
		fullName,
		userPhone: _req.user.phone || '',
	});
});

app.post('/orders/new', requireAuth, async (req, res) => {
	const rxFio = /^[А-Яа-яЁё\s\-]{5,60}$/;
	const rxPhone = /^\+7\d{10}$/;

	const { customer_name, customer_phone, product_name, quantity, unit_price, product_link, delivery_date, user_comment } = req.body;

	if (!product_name || product_name.length < 1 || product_name.length > 255) {
		return res.status(400).send('Название товара: от 1 до 255 символов');
	}

	const qty = Number(quantity);
	if (!Number.isInteger(qty) || qty < 1 || qty > 10000) {
		return res.status(400).send('Количество: целое число от 1 до 10000');
	}

	if (product_link && String(product_link).length > 32767) {
		return res.status(400).send('Ссылка на товар: не более 32767 символов');
	}

	const price = Number(unit_price);
	if (Number.isNaN(price) || price < 1 || price > 100_000_000) {
		return res.status(400).send('Цена: от 1 до 100 000 000');
	}

	if (!rxFio.test(String(customer_name || ''))) {
		return res.status(400).send('ФИО: только русские буквы, пробелы и дефис');
	}

	if (!rxPhone.test(String(customer_phone || ''))) {
		return res.status(400).send('Телефон: формат +7XXXXXXXXXX');
	}

	 if (user_comment && String(user_comment).length > 500) {
    return res.status(400).send('Комментарий: максимум 500 символов');
  }

  await insertOrder({
    ...req.body,
    user_id: req.user.id,
    user_comment: user_comment || null
  });

  res.redirect('/orders/my');
});

app.get('/orders/edit/:id', requireAuth, async (req, res) => {
	const order = await getOrderByIdAndUser(req.params.id, req.user.id);
	if (!order || order.status !== 'На рассмотрении') return res.redirect('/orders/my');
	return res.render('editOrder', { title: 'Редактировать заказ', order });
});

app.post('/orders/edit/:id', requireAuth, async (req, res) => {
	await editOrderByUser(req.user.id, req.params.id, req.body);
	return res.redirect('/orders/my');
});

app.post('/orders/update-user/:id', requireAuth, async (req, res) => {
	const { product_link, delivery_date } = req.body;
	await updateOrderLinkAndDate(req.params.id, req.user.id, product_link, delivery_date);
	return res.redirect('/orders/my');
});

app.post('/orders/cancel/:id', requireAuth, async (req, res) => {
	const order = await getOrderByIdAndUser(req.params.id, req.user.id);
	if (!order || order.status !== 'На рассмотрении') return res.redirect('/orders/my');
	await updateOrderStatus(req.params.id, 'Отменено');
	return res.redirect('/orders/my');
});

// ---------- orders: admin ----------
app.get('/orders/active', requireAuth, requireAdmin, async (req, res) => {
	const loginFilter = req.query.login?.trim() || null;
	const orders = await getActiveOrders(loginFilter);

	return res.render('activeOrders', {
		title: 'Активные заказы',
		isOrdersPage: true,
		orders,
		loginFilter,
	});
});

app.post('/orders/admin-action/:id', requireAuth, requireAdmin, async (req, res) => {
  const oid = Number(req.params.id);

  const status = String(req.body.status || '').trim();
  const adminComment = String(req.body.admin_comment || '').trim();

  if (!allowedStatuses.includes(status)) {
    return res.status(400).send(`Bad status: "${status}"`);
  }

  if (adminComment.length > 500) {
    return res.status(400).send('Комментарий: максимум 500 символов');
  }

  await updateOrderAdminAction(oid, status, adminComment);
  return res.redirect('/orders/active');
});



app.get('/orders/archive', requireAuth, requireAdmin, async (_req, res) => {
	const orders = await getArchiveOrders();
	return res.render('archive', {
		title: 'Архив заказов',
		isOrdersPage: true,
		orders,
	});
});

app.post('/orders/update-status/:id', requireAuth, requireAdmin, async (req, res) => {
	const { status } = req.body;
	if (!allowedStatuses.includes(status)) return res.status(400).send('Bad status');
	await updateOrderStatus(req.params.id, status);
	return res.redirect('/orders/active');
});

app.post('/orders/update-eta/:id', requireAuth, requireAdmin, async (req, res) => {
	await updateOrderETA(req.params.id, req.body.delivery_date);
	return res.redirect('/orders/active');
});

app.post('/orders/update-admin/:id', requireAuth, requireAdmin, async (req, res) => {
	const { product_link, delivery_date, unit_price } = req.body;
	const todayTs = new Date().setHours(0, 0, 0, 0);

	if (new Date(delivery_date).getTime() < todayTs) {
		return res.status(400).send('Дата доставки не может быть в прошлом');
	}
	if (Number(unit_price) < 0) {
		return res.status(400).send('Цена не может быть отрицательной');
	}

	await updateOrderAdmin(req.params.id, product_link, delivery_date, unit_price);
	return res.redirect('/orders/active');
});

// ---------- admin: users ----------
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
	const loginFilter = req.query.login?.trim() || null;
	const users = await getAllUsers(loginFilter);

	return res.render('adminUsers', {
		title: 'БД пользователей',
		users,
		loginFilter,
		isOrdersPage: true,
	});
});

app.post('/admin/users/:id/password', requireAuth, requireAdmin, async (req, res) => {
	const { password } = req.body;
	// если updateUserPassword ожидает уже hash — захешируй тут:
	const hash = await bcrypt.hash(String(password), SALT_ROUNDS);
	await updateUserPassword(req.params.id, hash);
	return res.redirect('/admin/users');
});

app.post('/admin/users/:id/delete', requireAuth, requireAdmin, async (req, res) => {
	await deleteUser(req.params.id);
	return res.redirect('/admin/users');
});

// ban/unban
app.post('/admin/users/:id/ban', requireAuth, requireAdmin, async (req, res) => {
	const userId = Number(req.params.id);
	const adminId = req.user.id;

	const reason = String(req.body.reason || '').trim();
	const duration = String(req.body.duration || 'permanent').trim(); // permanent | 1 | 7 | 30 ...

	if (!reason || reason.length > 500) return res.status(400).send('Причина бана: 1–500 символов');

	let bannedUntil = null;
	if (duration !== 'permanent') {
		const days = Number(duration);
		if (!Number.isInteger(days) || days < 1 || days > 3650) return res.status(400).send('Некорректный срок бана');
		const d = new Date();
		d.setDate(d.getDate() + days);
		bannedUntil = d;
	}

	await banUser(userId, adminId, reason, bannedUntil);
	return res.redirect('/admin/users');
});

app.post('/admin/users/:id/unban', requireAuth, requireAdmin, async (req, res) => {
	await unbanUser(req.params.id);
	return res.redirect('/admin/users');
});

// ---------- Mail.ru OAuth ----------
// ENV:
// MAILRU_CLIENT_ID=...
// MAILRU_CLIENT_SECRET=...
// MAILRU_REDIRECT_URI=http://localhost:3000/auth/mailru/callback

app.get('/auth/mailru', (req, res) => {
	const state = crypto.randomBytes(16).toString('hex');
	res.cookie('mailru_state', state, authCookieOptions(10 * 60 * 1000)); // 10 минут

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

		const expectedState = req.cookies?.mailru_state;
		if (!state || !expectedState || String(state) !== String(expectedState)) {
			return res.status(400).send('Bad state');
		}
		res.clearCookie('mailru_state');

		if (!code) return res.status(400).send('No code');

		// 1) code -> access_token
		const tokenResp = await axios.post(
			'https://o2.mail.ru/token',
			new URLSearchParams({
				grant_type: 'authorization_code',
				code: String(code),
				redirect_uri: process.env.MAILRU_REDIRECT_URI,
				client_id: process.env.MAILRU_CLIENT_ID,
				client_secret: process.env.MAILRU_CLIENT_SECRET,
			}).toString(),
			{ headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 }
		);

		const accessToken = tokenResp.data?.access_token;
		if (!accessToken) return res.redirect('/login');

		// 2) userinfo
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

		if (userInfoResp.status !== 200) {
			console.error('MAILRU USERINFO FAIL:', userInfoResp.status, userInfoResp.data);
			return res.redirect('/login');
		}

		const info = userInfoResp.data || {};
		const email = info.email;
		if (!email) return res.status(400).send('Mail.ru не вернул email');

		// 3) ищем пользователя по email
		let user = await getUserByEmail(email);

		// 4) если нет — создаём
		if (!user) {
			const fullName = String(info.name || '').trim();
			const firstName = String(info.first_name || '').trim();
			const lastName = String(info.last_name || '').trim();

			const name = firstName || (fullName.split(' ')[1] || fullName.split(' ')[0] || 'Пользователь');
			const surname = lastName || (fullName.split(' ')[0] || 'MailRu');

			await insertOAuthUserFromMailru({
				email,
				name,
				surname,
				patronymic: null,
				phone: null,
			});

			user = await getUserByEmail(email);
			if (!user) return res.redirect('/login');
		}

		// 5) проверка бана
		const ban = await getActiveBanByUserId(user.id);
		if (ban) {
			const untilText = ban.banned_until ? `до ${new Date(ban.banned_until).toLocaleString('ru-RU')}` : 'навсегда';
			return res.render('auth/login', {
				title: 'Вход',
				isLoginPage: true,
				error: `Аккаунт заблокирован ${untilText}. Причина: ${ban.reason}`,
			});
		}

		// 6) создаём DB-сессию и кладём auth_token
		const { selector, validator, cookieValue } = makeSessionToken();
		const tokenHash = await bcrypt.hash(validator, SALT_ROUNDS);

		const expiresAt = new Date();
		expiresAt.setDate(expiresAt.getDate() + 1);

		await createDbSession({
			userId: user.id,
			selector,
			tokenHash,
			expiresAt,
			ip: req.ip,
			userAgent: req.get('user-agent') || null,
		});

		res.cookie('auth_token', cookieValue, authCookieOptions(1000 * 60 * 60 * 24));

		return res.redirect(user.role === 'admin' ? '/orders/active' : '/orders/my');
	} catch (e) {
		console.error('MAILRU CALLBACK ERROR:', e);
		return res.redirect('/login');
	}
});

// ---------- start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
