import { Router } from 'express';
const router = Router();

// Страница профиля
router.get('/', (req, res) => {
  res.render('profile', { title: 'Мой профиль' });
});

export default router; // ВАЖНО: ОБЯЗАТЕЛЬНО
