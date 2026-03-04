import api from './api';

export const authService = {
  register: (payload) => api.post('/auth/register', payload),
  login: (payload) => api.post('/auth/login', payload),
  logout: () => api.post('/auth/logout'),
  me: () => api.get('/auth/me'),
  requestEmailOtp: (payload) => api.post('/auth/request-email-otp', payload),
  verifyEmailOtp: (payload) => api.post('/auth/verify-email-otp', payload),
  requestPhoneOtp: (payload) => api.post('/auth/request-phone-otp', payload),
  verifyPhoneOtp: (payload) => api.post('/auth/verify-phone-otp', payload),
  googleLogin: (payload) => api.post('/auth/oauth/google', payload),
  appleLogin: (payload) => api.post('/auth/oauth/apple', payload)
};
