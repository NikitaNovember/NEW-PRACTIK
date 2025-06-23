import { Router } from 'express';
const router = Router();

// Страница "Мои заказы"
router.get('/my', (req, res) => {
  res.render('myOrders', { title: 'Мои заказы' });
});

// Страница "Активные заказы"
router.get('/active', (req, res) => {
  res.render('activeOrders', { title: 'Активные заказы' });
});

// Страница "Архив заказов"
router.get('/archive', (req, res) => {
  res.render('archive', { title: 'Архив заказов' });
});

// Страница "Оформить заказ"
router.get('/new', (req, res) => {
  res.render('newOrder', { title: 'Оформить заказ' });
});

export default router; // ОБЯЗАТЕЛЬНО
