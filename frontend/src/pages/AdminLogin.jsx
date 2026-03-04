import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function AdminLogin() {
  const navigate = useNavigate();
  const { login, logout } = useAuth();
  const [form, setForm] = useState({ email: '', password: '', recaptchaToken: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(form);
      const token = localStorage.getItem('hf_access_token');
      if (!token) {
        throw new Error('Login failed');
      }

      // ensure fresh user role loaded by context login(); if not admin, force logout
      const meRes = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000/api'}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const me = await meRes.json();
      if (!me?.is_admin) {
        await logout();
        setError('Admin access required. Use an admin account.');
        return;
      }

      navigate('/admin');
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to login');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="hf-container auth-page">
      <h1>Admin Login</h1>
      <p>Authorized staff only.</p>

      <form className="form-grid" onSubmit={submit}>
        <input
          type="email"
          placeholder="Admin email"
          value={form.email}
          onChange={(e) => setForm((prev) => ({ ...prev, email: e.target.value }))}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={form.password}
          onChange={(e) => setForm((prev) => ({ ...prev, password: e.target.value }))}
          required
        />
        <input
          placeholder="reCAPTCHA token"
          value={form.recaptchaToken}
          onChange={(e) => setForm((prev) => ({ ...prev, recaptchaToken: e.target.value }))}
        />
        <button type="submit" disabled={loading}>{loading ? 'Signing in...' : 'Login as Admin'}</button>
      </form>

      {error ? <p style={{ color: '#c0392b' }}>{error}</p> : null}

      <p>
        Customer account? <Link to="/login">Go to user login</Link>
      </p>
    </div>
  );
}

export default AdminLogin;
