import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import api from '../services/api';
import { useTheme } from '../context/ThemeContext';

const SHOP_LINKS = [
  { label: 'Men', to: '/shop?category=men' },
  { label: 'Women', to: '/shop?category=women' },
  { label: 'New Arrivals', to: '/shop?sort=new' },
  { label: 'On Sale', to: '/shop?sort=price_desc' },
  { label: 'Compression Wear', to: '/shop?category=men-compression' },
  { label: 'Workout Shorts', to: '/shop?category=men-shorts' },
  { label: 'Gym T-Shirts', to: '/shop?category=men-t-shirts' }
];

const SUPPORT_LINKS = [
  { label: 'Contact Us', to: '/company#contact', anchor: true },
  { label: 'FAQs', to: '/company#faqs', anchor: true },
  { label: 'Shipping Information', to: '/company#shipping', anchor: true },
  { label: 'Track Order', to: '/company#track-order', anchor: true },
  { label: 'Returns & Exchanges', to: '/company#returns', anchor: true },
  { label: 'Size Guide', to: '/company#size-guide', anchor: true }
];

const COMPANY_LINKS = [
  { label: 'About HyperFit', to: '/company#about', anchor: true },
  { label: 'Sitemap', to: '/sitemap' }
];

const LEGAL_LINKS = [
  { label: 'Terms of Use', to: '/legals/terms-of-use' },
  { label: 'Privacy Policy', to: '/legals/privacy-policy' },
  { label: 'Refund Policy', to: '/legals/refund-policy' },
  { label: 'Cookie Policy', to: '/legals/cookie-policy' }
];

const SOCIAL_LINKS = [
  { name: 'Instagram', href: 'https://instagram.com' },
  { name: 'Facebook', href: 'https://facebook.com' },
  { name: 'X', href: 'https://x.com' },
  { name: 'YouTube', href: 'https://youtube.com' }
];

const TRUST_ITEMS = [
  { title: '100% Authentic Products', subtitle: 'Guaranteed original HyperFit products', icon: 'shield' },
  { title: '30 Day Returns', subtitle: 'Easy return and exchange policy', icon: 'return' },
  { title: 'Secure Payments', subtitle: 'Encrypted and trusted checkout flow', icon: 'lock' },
  { title: 'Fast Shipping', subtitle: 'Quick dispatch and order tracking', icon: 'truck' }
];

const POPULAR_SEARCHES = [
  'gym t shirts',
  'compression shirts',
  'workout shorts',
  'gym wear men',
  'activewear women',
  'fitness clothing',
  'training pants',
  'sports bras',
  'gym leggings'
];

function SocialLogo({ name }) {
  if (name === 'Instagram') {
    return (
      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <rect x="3" y="3" width="18" height="18" rx="5" />
        <circle cx="12" cy="12" r="4" />
        <circle cx="17" cy="7" r="1" fill="currentColor" stroke="none" />
      </svg>
    );
  }

  if (name === 'Facebook') {
    return (
      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="currentColor" aria-hidden="true">
        <path d="M13.3 21v-7h2.4l.4-3h-2.8V9.1c0-.9.3-1.5 1.6-1.5h1.3V5c-.2 0-1-.1-2-.1-2 0-3.4 1.2-3.4 3.5V11H8.7v3h2.1v7h2.5z" />
      </svg>
    );
  }

  if (name === 'X') {
    return (
      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="currentColor" aria-hidden="true">
        <path d="M18.9 3h2.8l-6.2 7.1L23 21h-6l-4.7-6.2L6.9 21H4l6.6-7.5L1.5 3h6.2l4.2 5.6L18.9 3zm-1 16.3h1.5L6.9 4.6H5.3L17.9 19.3z" />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="currentColor" aria-hidden="true">
      <path d="M21.8 8.2a2.8 2.8 0 0 0-2-2c-1.8-.5-7.8-.5-7.8-.5s-6 0-7.8.5a2.8 2.8 0 0 0-2 2A29 29 0 0 0 2 12a29 29 0 0 0 .2 3.8 2.8 2.8 0 0 0 2 2c1.8.5 7.8.5 7.8.5s6 0 7.8-.5a2.8 2.8 0 0 0 2-2A29 29 0 0 0 22 12a29 29 0 0 0-.2-3.8zM10 15.2V8.8l5.6 3.2-5.6 3.2z" />
    </svg>
  );
}

function TrustIcon({ type, isDark }) {
  const colorClass = isDark ? 'text-slate-100' : 'text-slate-700';

  if (type === 'shield') {
    return (
      <svg viewBox="0 0 24 24" className={`h-4 w-4 ${colorClass}`} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M12 3l7 3v6c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6l7-3z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    );
  }

  if (type === 'return') {
    return (
      <svg viewBox="0 0 24 24" className={`h-4 w-4 ${colorClass}`} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M4 7h10a6 6 0 0 1 0 12H7" />
        <path d="M7 19l-3-3 3-3" />
      </svg>
    );
  }

  if (type === 'lock') {
    return (
      <svg viewBox="0 0 24 24" className={`h-4 w-4 ${colorClass}`} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <rect x="5" y="11" width="14" height="10" rx="2" />
        <path d="M8 11V8a4 4 0 1 1 8 0v3" />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" className={`h-4 w-4 ${colorClass}`} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 7h12l4 4v6H3z" />
      <circle cx="7" cy="17" r="2" />
      <circle cx="17" cy="17" r="2" />
      <path d="M15 7v4h4" />
    </svg>
  );
}

function FooterLink({ item, isDark }) {
  const base = `group inline-flex items-center text-sm transition ${isDark ? 'text-slate-300 hover:text-white' : 'text-slate-600 hover:text-slate-900'}`;

  if (item.external) {
    return (
      <a href={item.to} target="_blank" rel="noreferrer" className={base}>
        <span className="relative">
          {item.label}
          <span className={`absolute -bottom-0.5 left-0 h-px w-0 transition-all duration-200 group-hover:w-full ${isDark ? 'bg-slate-200' : 'bg-slate-700'}`} />
        </span>
      </a>
    );
  }

  if (item.anchor) {
    return (
      <a href={item.to} className={base}>
        <span className="relative">
          {item.label}
          <span className={`absolute -bottom-0.5 left-0 h-px w-0 transition-all duration-200 group-hover:w-full ${isDark ? 'bg-slate-200' : 'bg-slate-700'}`} />
        </span>
      </a>
    );
  }

  return (
    <Link to={item.to} className={base}>
      <span className="relative">
        {item.label}
        <span className={`absolute -bottom-0.5 left-0 h-px w-0 transition-all duration-200 group-hover:w-full ${isDark ? 'bg-slate-200' : 'bg-slate-700'}`} />
      </span>
    </Link>
  );
}

function FooterColumn({ title, links, isDark }) {
  return (
    <section className="space-y-3">
      <h4 className="m-0 text-xs font-bold uppercase tracking-[0.14em]">{title}</h4>
      <nav aria-label={title} className="grid gap-2">
        {links.map((item) => <FooterLink key={item.label} item={item} isDark={isDark} />)}
      </nav>
    </section>
  );
}

function SocialIcons({ isDark }) {
  return (
    <section className="space-y-3">
      <h4 className="m-0 text-xs font-bold uppercase tracking-[0.14em]">Keep in Touch</h4>
      <div className="flex flex-wrap gap-2">
        {SOCIAL_LINKS.map((item) => (
          <motion.a
            whileHover={{ scale: 1.06 }}
            whileTap={{ scale: 0.96 }}
            key={item.name}
            href={item.href}
            target="_blank"
            rel="noreferrer"
            aria-label={item.name}
            className={`grid h-10 w-10 place-items-center rounded-full border transition ${isDark ? 'border-slate-600 bg-slate-800 text-slate-200 hover:border-slate-400' : 'border-slate-300 bg-white text-slate-700 hover:border-slate-500'}`}
          >
            <SocialLogo name={item.name} />
          </motion.a>
        ))}
      </div>
    </section>
  );
}

function TrustIndicators({ isDark }) {
  return (
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {TRUST_ITEMS.map((item) => (
        <article key={item.title} className={`rounded-2xl border p-3 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}>
          <div className="flex items-start gap-3">
            <span className={`mt-0.5 grid h-8 w-8 place-items-center rounded-full ${isDark ? 'bg-slate-700' : 'bg-slate-100'}`}>
              <TrustIcon type={item.icon} isDark={isDark} />
            </span>
            <div>
              <p className="m-0 text-sm font-semibold">{item.title}</p>
              <p className={`m-0 mt-1 text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{item.subtitle}</p>
            </div>
          </div>
        </article>
      ))}
    </section>
  );
}

function FooterNewsletterForm({ isDark }) {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState('idle');
  const [message, setMessage] = useState('');

  const submit = async (event) => {
    event.preventDefault();
    if (!email.trim()) return;

    setStatus('loading');
    setMessage('');
    try {
      const { data } = await api.post('/marketing/newsletter-subscribe', { email });
      setStatus('success');
      setMessage(data.message || 'Subscribed successfully');
      setEmail('');
    } catch (error) {
      setStatus('error');
      setMessage(error?.response?.data?.error || 'Unable to subscribe. Try again.');
    }
  };

  return (
    <section className="space-y-3">
      <h4 className="m-0 text-sm font-semibold">Stay Updated</h4>
      <form className="flex flex-col gap-2 sm:flex-row" onSubmit={submit}>
        <input
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          placeholder="Email address"
          required
          className={`w-full rounded-full border px-4 py-2 text-sm outline-none transition focus:ring-2 ${isDark ? 'border-slate-600 bg-slate-900 text-slate-100 focus:ring-slate-500' : 'border-slate-300 bg-white text-slate-800 focus:ring-slate-300'}`}
        />
        <button
          type="submit"
          disabled={status === 'loading'}
          className={`rounded-full px-5 py-2 text-xs font-semibold uppercase tracking-[0.08em] transition disabled:opacity-40 ${isDark ? 'bg-slate-100 text-slate-900 hover:bg-white' : 'bg-slate-900 text-white hover:bg-black'}`}
        >
          {status === 'loading' ? 'Subscribing...' : 'Subscribe'}
        </button>
      </form>
      {message ? <p className={`m-0 text-xs ${status === 'error' ? 'text-rose-500' : isDark ? 'text-emerald-300' : 'text-emerald-600'}`}>{message}</p> : null}
    </section>
  );
}

function PopularSearches({ isDark }) {
  return (
    <section className={`mt-6 border-t pt-5 ${isDark ? 'border-slate-700' : 'border-slate-300'}`}>
      <h4 className="m-0 text-xs font-bold uppercase tracking-[0.14em]">Popular Searches</h4>
      <div className="mt-3 hidden flex-wrap gap-x-3 gap-y-2 md:flex">
        {POPULAR_SEARCHES.map((item) => (
          <Link key={item} to={`/shop?search=${encodeURIComponent(item)}`} className={`text-sm transition hover:underline ${isDark ? 'text-slate-300 hover:text-white' : 'text-slate-600 hover:text-slate-900'}`}>
            {item}
          </Link>
        ))}
      </div>

      <div className="mt-3 flex gap-2 overflow-x-auto pb-1 md:hidden">
        {POPULAR_SEARCHES.map((item) => (
          <Link
            key={item}
            to={`/shop?search=${encodeURIComponent(item)}`}
            className={`whitespace-nowrap rounded-full border px-3 py-1 text-xs ${isDark ? 'border-slate-600 bg-slate-800 text-slate-200' : 'border-slate-300 bg-white text-slate-700'}`}
          >
            {item}
          </Link>
        ))}
      </div>
    </section>
  );
}

function FooterBottomBar({ isDark }) {
  return (
    <div className={`mt-6 border-t pt-4 text-sm ${isDark ? 'border-slate-700 text-slate-400' : 'border-slate-300 text-slate-600'}`}>
      <div className="grid gap-2 text-center md:grid-cols-3 md:text-left">
        <a href="mailto:support@hyperfit.com" className="hover:underline">Have issues? Contact Support</a>
        <p className="m-0 text-center">© 2026 HyperFit. All rights reserved.</p>
        <p className="m-0 md:text-right">Built with HyperFit Performance Wear</p>
      </div>
    </div>
  );
}

function MobileAccordionColumn({ title, links, open, onToggle, isDark }) {
  return (
    <section className={`rounded-xl border md:hidden ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}>
      <button type="button" onClick={onToggle} className="flex w-full items-center justify-between px-4 py-3 text-left text-sm font-semibold uppercase tracking-[0.08em]">
        {title}
        <span>{open ? '-' : '+'}</span>
      </button>
      <AnimatePresence>
        {open ? (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden px-4 pb-4">
            <div className="grid gap-2">
              {links.map((item) => <FooterLink key={item.label} item={item} isDark={isDark} />)}
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </section>
  );
}

function Footer() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const [openSection, setOpenSection] = useState('SHOP');

  const columns = useMemo(() => [
    { title: 'SHOP', links: SHOP_LINKS },
    { title: 'CUSTOMER SUPPORT', links: SUPPORT_LINKS },
    { title: 'COMPANY', links: COMPANY_LINKS },
    { title: 'LEGAL', links: LEGAL_LINKS }
  ], []);

  return (
    <footer className={`hf-footer border-t ${isDark ? 'border-slate-700 bg-slate-950 text-slate-100' : 'border-slate-200 bg-slate-100 text-slate-900'}`}>
      <div className="hf-container py-8 md:py-10">
        <div className="hidden gap-6 md:grid md:grid-cols-4">
          {columns.map((column) => <FooterColumn key={column.title} title={column.title} links={column.links} isDark={isDark} />)}
        </div>

        <div className="space-y-3 md:hidden">
          {columns.map((column) => (
            <MobileAccordionColumn
              key={column.title}
              title={column.title}
              links={column.links}
              open={openSection === column.title}
              onToggle={() => setOpenSection((prev) => (prev === column.title ? '' : column.title))}
              isDark={isDark}
            />
          ))}
        </div>

        <div className="mt-6 grid gap-6 lg:grid-cols-[1.2fr_1fr]">
          <TrustIndicators isDark={isDark} />
          <div className="space-y-5">
            <FooterNewsletterForm isDark={isDark} />
            <SocialIcons isDark={isDark} />
          </div>
        </div>

        <PopularSearches isDark={isDark} />
        <FooterBottomBar isDark={isDark} />
      </div>
    </footer>
  );
}

export default Footer;
