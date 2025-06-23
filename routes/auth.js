// routes/auth.js
import { Router } from 'express';
const router = Router();

router.get('/', (req, res) => {
  res.redirect('/login');
});

router.get('/login', (req, res) => {
  res.render('auth/login', { title: 'Вход в систему' });
});

export default router; // вот так должно быть
