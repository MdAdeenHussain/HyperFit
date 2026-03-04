import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/authService';

function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [form, setForm] = useState({ email: '', password: '', recaptchaToken: '' });

  const submit = async (e) => {
    e.preventDefault();
    await login(form);
    navigate('/account');
  };

  return (
    <div className="hf-container auth-page">
      <h1>Login</h1>
      <form className="form-grid" onSubmit={submit}>
        <input type="email" placeholder="Email" value={form.email} onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))} required />
        <input type="password" placeholder="Password" value={form.password} onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))} required />
        <input placeholder="reCAPTCHA token" value={form.recaptchaToken} onChange={(e) => setForm((p) => ({ ...p, recaptchaToken: e.target.value }))} />
        <button type="submit">Login</button>
      </form>

      <div className="oauth-row">
        <button onClick={() => authService.googleLogin({ email: 'google@hyperfit.com', google_id: `g_${Date.now()}` }).then(() => navigate('/account'))}>Google Login</button>
        <button onClick={() => authService.appleLogin({ email: 'apple@hyperfit.com', apple_id: `a_${Date.now()}` }).then(() => navigate('/account'))}>Apple Login</button>
      </div>

      <p>Don&apos;t have an account? <Link to="/register">Register</Link></p>
    </div>
  );
}

export default Login;
