import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { setMeta } from '../utils/helpers';

const SITEMAP_GROUPS = [
  {
    title: 'Shop',
    links: [
      { label: 'Shop Men', to: '/shop?category=men' },
      { label: 'Shop Women', to: '/shop?category=women' },
      { label: 'New Arrivals', to: '/shop?sort=new' },
      { label: 'Best Sellers', to: '/shop?sort=best_selling' }
    ]
  },
  {
    title: 'Customer',
    links: [
      { label: 'Account', to: '/account' },
      { label: 'Orders & Returns', to: '/account?tab=orders' },
      { label: 'Addresses', to: '/account?tab=addresses' },
      { label: 'Wishlist', to: '/wishlist' }
    ]
  },
  {
    title: 'Company',
    links: [
      { label: 'About HyperFit', to: '/company#about' },
      { label: 'Contact', to: '/company#contact' },
      { label: 'FAQs', to: '/company#faqs' }
    ]
  },
  {
    title: 'Legal',
    links: [
      { label: 'Terms of Use', to: '/legals/terms-of-use' },
      { label: 'Privacy Policy', to: '/legals/privacy-policy' },
      { label: 'Refund Policy', to: '/legals/refund-policy' },
      { label: 'Cookie Policy', to: '/legals/cookie-policy' }
    ]
  }
];

function SitemapPage() {
  useEffect(() => {
    setMeta({
      title: 'Sitemap | HyperFit',
      description: 'Navigate all major pages of the HyperFit website from this sitemap.'
    });
  }, []);

  return (
    <div className="hf-container page-gap">
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card-block">
        <p className="eyebrow">Navigation</p>
        <h1 className="m-0 text-3xl">Sitemap</h1>
        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Browse all key HyperFit pages and support resources.</p>
      </motion.section>

      <section className="grid gap-4 md:grid-cols-2">
        {SITEMAP_GROUPS.map((group, index) => (
          <motion.article
            key={group.title}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.05 }}
            className="card-block"
          >
            <h2 className="m-0 text-lg">{group.title}</h2>
            <ul className="mt-3 grid gap-2 p-0" style={{ listStyle: 'none' }}>
              {group.links.map((item) => (
                <li key={item.label}>
                  <Link className="text-link" to={item.to}>{item.label}</Link>
                </li>
              ))}
            </ul>
          </motion.article>
        ))}
      </section>
    </div>
  );
}

export default SitemapPage;
