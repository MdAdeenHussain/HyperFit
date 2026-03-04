import axios from 'axios';
import { API_BASE_URL } from '../utils/constants';

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('hf_access_token');
  const csrfToken = localStorage.getItem('hf_csrf_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  if (csrfToken) config.headers['X-CSRF-Token'] = csrfToken;
  return config;
});

export async function bootstrapCsrf() {
  const { data } = await api.get('/auth/csrf-token');
  localStorage.setItem('hf_csrf_token', data.csrf_token);
  return data.csrf_token;
}

export default api;
