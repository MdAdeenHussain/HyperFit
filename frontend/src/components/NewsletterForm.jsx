import { useState } from 'react';

function NewsletterForm({ compact = false }) {
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);

  return (
    <form
      className={compact ? 'newsletter-row' : 'newsletter-form'}
      onSubmit={(event) => {
        event.preventDefault();
        if (!email.trim()) return;
        setSubmitted(true);
        setEmail('');
      }}
    >
      <input
        type="email"
        placeholder="Enter your email"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
        aria-label="Email address"
      />
      <button type="submit">Subscribe</button>
      {submitted && <small>Thanks for subscribing.</small>}
    </form>
  );
}

export default NewsletterForm;
