// Импорты основных модулей
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import fileUpload from 'express-fileupload';
import path from 'path';
import { fileURLToPath } from 'url';
import expressHbs from 'express-handlebars';
import dotenv from 'dotenv';
dotenv.config();

// Получение абсолютного пути
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Инициализация Express
const app = express();

// Настройка шаблонизатора Handlebars
const hbs = expressHbs.create({
  extname: '.hbs',
  defaultLayout: 'main',
  layoutsDir: path.join(__dirname, 'views', 'layouts'),
  partialsDir: path.join(__dirname, 'views', 'partials'),
  helpers: {
    eq: (a, b) => a == b,
    capitalize: str => typeof str === 'string' ? str.charAt(0).toUpperCase() + str.slice(1) : '',
    skillLabel: (key) => {
      const labels = {
        independence: 'Самостоятельность',
        creativity: 'Креативность'
      };
      return labels[key] || key;
    }
  }
});

app.engine('.hbs', hbs.engine);
app.set('view engine', '.hbs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(fileUpload());
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecretkey',
  resave: false,
  saveUninitialized: false
}));

// Подключение статики
app.use(express.static(path.join(__dirname, 'public')));

// Роуты
import authRoutes from './routes/auth.js';
import profileRoutes from './routes/profile.js';
import ordersRoutes from './routes/orders.js';

app.use('/', authRoutes);
app.use('/profile', profileRoutes);
app.use('/orders', ordersRoutes);

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен: http://localhost:${PORT}`);
});
