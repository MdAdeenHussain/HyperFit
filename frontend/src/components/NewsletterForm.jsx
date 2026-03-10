import { useState } from 'react';
import api from '../services/api';

function NewsletterForm({ compact = false }) {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState('idle');
  const [message, setMessage] = useState('');

  return (
    <form
      className={compact ? 'newsletter-row' : 'newsletter-form'}
      onSubmit={async (event) => {
        event.preventDefault();
        if (!email.trim()) return;

        setStatus('loading');
        setMessage('');

        try {
          const { data } = await api.post('/marketing/newsletter-subscribe', { email });
          setStatus('success');
          setMessage(data.message || 'Subscribed successfully.');
          setEmail('');
        } catch (error) {
          setStatus('error');
          setMessage(error?.response?.data?.error || 'Unable to subscribe right now.');
        }
      }}
    >
      <input
        type="email"
        placeholder="Enter your email"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
        aria-label="Email address"
      />
      <button type="submit" disabled={status === 'loading'}>{status === 'loading' ? 'Subscribing...' : 'Subscribe'}</button>
      {message ? <small>{message}</small> : null}
    </form>
  );
}

export default NewsletterForm;
