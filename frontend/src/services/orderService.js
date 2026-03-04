import api from './api';

export const orderService = {
  checkout: (payload) => api.post('/orders/checkout', payload),
  myOrders: () => api.get('/orders'),
  getOrder: (orderNumber) => api.get(`/orders/${orderNumber}`),
  trackOrder: (orderNumber) => api.get(`/orders/${orderNumber}/track`),
  createPayment: (payload) => api.post('/payments/create', payload),
  verifyPayment: (payload) => api.post('/payments/verify', payload)
};
