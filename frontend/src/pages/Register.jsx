import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/authService';

function Register() {
  const navigate = useNavigate();
  const { register } = useAuth();
  const [form, setForm] = useState({ first_name: '', last_name: '', email: '', phone: '', password: '', recaptchaToken: '' });
  const [emailOtp, setEmailOtp] = useState('');
  const [phoneOtp, setPhoneOtp] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    await register(form);
    await authService.requestEmailOtp({ email: form.email });
    if (form.phone) await authService.requestPhoneOtp({ phone: form.phone });
    alert('Registered. Verify OTP to complete account setup.');
  };

  const verifyOtp = async () => {
    if (emailOtp) await authService.verifyEmailOtp({ email: form.email, otp: emailOtp });
    if (phoneOtp && form.phone) await authService.verifyPhoneOtp({ phone: form.phone, otp: phoneOtp });
    navigate('/account');
  };

  return (
    <div className="hf-container auth-page">
      <h1>Register</h1>
      <form className="form-grid" onSubmit={submit}>
        <input placeholder="First name" value={form.first_name} onChange={(e) => setForm((p) => ({ ...p, first_name: e.target.value }))} required />
        <input placeholder="Last name" value={form.last_name} onChange={(e) => setForm((p) => ({ ...p, last_name: e.target.value }))} required />
        <input type="email" placeholder="Email" value={form.email} onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))} required />
        <input placeholder="Phone" value={form.phone} onChange={(e) => setForm((p) => ({ ...p, phone: e.target.value }))} />
        <input type="password" placeholder="Password" value={form.password} onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))} required />
        <input placeholder="reCAPTCHA token" value={form.recaptchaToken} onChange={(e) => setForm((p) => ({ ...p, recaptchaToken: e.target.value }))} />
        <button type="submit">Create Account</button>
      </form>

      <div className="otp-section">
        <input placeholder="Email OTP" value={emailOtp} onChange={(e) => setEmailOtp(e.target.value)} />
        <input placeholder="Phone OTP" value={phoneOtp} onChange={(e) => setPhoneOtp(e.target.value)} />
        <button onClick={verifyOtp}>Verify OTP</button>
      </div>
    </div>
  );
}

export default Register;
