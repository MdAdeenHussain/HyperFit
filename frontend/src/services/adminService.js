import api from './api';

const adminService = {
  getDashboard: (params = {}) => api.get('/admin/dashboard', { params }),

  getOrders: (params = {}) => api.get('/admin/orders', { params }),
  updateOrder: (orderNumber, payload) => api.patch(`/admin/orders/${orderNumber}`, payload),
  cancelOrder: (orderNumber) => api.post(`/admin/orders/${orderNumber}/cancel`),
  refundOrder: (orderNumber) => api.post(`/admin/orders/${orderNumber}/refund`),

  getProducts: (params = {}) => api.get('/admin/products', { params }),
  createProduct: (payload) => api.post('/admin/products', payload),
  updateProduct: (id, payload) => api.put(`/admin/products/${id}`, payload),
  deleteProduct: (id) => api.delete(`/admin/products/${id}`),

  getCategories: () => api.get('/admin/categories'),
  createCategory: (payload) => api.post('/admin/categories', payload),
  updateCategory: (id, payload) => api.put(`/admin/categories/${id}`, payload),
  deleteCategory: (id) => api.delete(`/admin/categories/${id}`),

  getInventory: () => api.get('/admin/inventory'),

  getCustomers: (params = {}) => api.get('/admin/customers', { params }),
  getCustomerProfile: (id) => api.get(`/admin/customers/${id}`),
  toggleCustomerBlock: (id, block) => api.patch(`/admin/customers/${id}/block`, { block }),

  getCoupons: () => api.get('/admin/coupons'),
  createCoupon: (payload) => api.post('/admin/coupons', payload),
  updateCoupon: (id, payload) => api.put(`/admin/coupons/${id}`, payload),
  deleteCoupon: (id) => api.delete(`/admin/coupons/${id}`),

  getCampaigns: () => api.get('/admin/campaigns'),
  sendCampaign: (payload) => api.post('/admin/campaigns/send', payload),

  getCmsPages: () => api.get('/admin/cms/pages'),
  getCmsPage: (pageKey) => api.get(`/admin/cms/pages/${pageKey}`),
  saveCmsDraft: (pageKey, content) => api.post(`/admin/cms/pages/${pageKey}/draft`, { content }),
  previewCms: (pageKey, content) => api.post(`/admin/cms/pages/${pageKey}/preview`, { content }),
  publishCms: (pageKey) => api.post(`/admin/cms/pages/${pageKey}/publish`),
  getCmsVersions: (pageKey) => api.get(`/admin/cms/pages/${pageKey}/versions`),
  restoreCmsVersion: (pageKey, versionId, publish = false) => api.post(`/admin/cms/pages/${pageKey}/versions/${versionId}/restore`, { publish }),

  getSiteSettings: () => api.get('/admin/settings/site'),
  updateSiteSettings: (value) => api.put('/admin/settings/site', { value }),

  getReportSummary: (params = {}) => api.get('/admin/reports/summary', { params }),

  getIntegrations: () => api.get('/admin/integrations')
};

export default adminService;
