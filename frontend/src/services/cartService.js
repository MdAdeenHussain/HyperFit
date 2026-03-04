import api from './api';

export const cartService = {
  getCart: () => api.get('/cart'),
  addItem: (payload) => api.post('/cart', payload),
  updateItem: (id, payload) => api.put(`/cart/${id}`, payload),
  removeItem: (id) => api.delete(`/cart/${id}`),
  applyCoupon: (code) => api.post('/cart/coupon', { code }),
  shippingEstimate: (pincode) => api.post('/cart/shipping-estimate', { pincode })
};
