import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { setMeta } from '../utils/helpers';

const SECTIONS = [
  {
    id: 'about',
    title: 'About HyperFit',
    body: 'HyperFit builds performance wear for athletes and everyday movers, blending minimalist aesthetics with utility-driven materials, fit precision, and lasting comfort.'
  },
  {
    id: 'contact',
    title: 'Contact Us',
    body: 'Reach us at support@hyperfit.com or +91 98765 43210. Support hours: Monday to Saturday, 9:00 AM to 8:00 PM IST.'
  },
  {
    id: 'faqs',
    title: 'FAQs',
    body: 'Find quick answers on orders, payments, shipping timelines, returns, size guide, and wallet/credits in your account center.'
  },
  {
    id: 'shipping',
    title: 'Shipping Information',
    body: 'Orders are usually dispatched within 24-48 hours. Delivery timelines vary by pincode and courier partner availability.'
  },
  {
    id: 'track-order',
    title: 'Track Order',
    body: 'Track every shipment from your account order history. Real-time shipment updates are provided once your order is dispatched.'
  },
  {
    id: 'returns',
    title: 'Returns & Exchanges',
    body: 'Eligible products can be returned or exchanged within 30 days, subject to product condition and return policy terms.'
  },
  {
    id: 'size-guide',
    title: 'Size Guide',
    body: 'Use our fit-first size recommendations on product pages. For training compression fits, choose your true size for optimal support.'
  }
];

function Company() {
  useEffect(() => {
    setMeta({
      title: 'Company | HyperFit',
      description: 'About HyperFit, customer support information, shipping details, returns, and FAQs.'
    });
  }, []);

  return (
    <div className="hf-container page-gap">
      <motion.section
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="card-block"
      >
        <p className="eyebrow">Company</p>
        <h1 className="m-0 text-3xl">HyperFit</h1>
        <p className="mt-2 max-w-3xl text-sm text-slate-500 dark:text-slate-400">
          Built for performance-first lifestyles. Explore brand information and support sections below.
        </p>
      </motion.section>

      <section className="grid gap-4">
        {SECTIONS.map((section, index) => (
          <motion.article
            key={section.id}
            id={section.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.05 }}
            className="card-block"
          >
            <h2 className="m-0 text-xl">{section.title}</h2>
            <p className="m-0 mt-2 text-sm text-slate-600 dark:text-slate-300">{section.body}</p>
          </motion.article>
        ))}
      </section>

      <section className="card-block">
        <h2 className="m-0 text-xl">Quick Links</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <Link className="text-link" to="/legals/terms-of-use">Terms of Use</Link>
          <Link className="text-link" to="/legals/privacy-policy">Privacy Policy</Link>
          <Link className="text-link" to="/legals/refund-policy">Refund Policy</Link>
          <Link className="text-link" to="/legals/cookie-policy">Cookie Policy</Link>
          <Link className="text-link" to="/sitemap">Sitemap</Link>
        </div>
      </section>
    </div>
  );
}

export default Company;
