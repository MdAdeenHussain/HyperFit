import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import CouponCard from './CouponCard';

const SORT_ITEMS = ['Trending', 'Discount', 'Expiring Soon', 'All'];

function CouponsPanel({ coupons = [], isDark }) {
  const [sort, setSort] = useState('Trending');

  const list = useMemo(() => {
    if (sort === 'All') return coupons;
    if (sort === 'Discount') return [...coupons].sort((a, b) => b.discount - a.discount);
    if (sort === 'Expiring Soon') return [...coupons].sort((a, b) => a.expiryDate - b.expiryDate);
    return [...coupons].sort((a, b) => b.trendingScore - a.trendingScore);
  }, [coupons, sort]);

  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <p className="m-0 mr-2 text-sm font-semibold">Sort by:</p>
        {SORT_ITEMS.map((item) => (
          <button
            key={item}
            type="button"
            onClick={() => setSort(item)}
            className={`rounded-full border px-4 py-2 text-sm font-medium ${sort === item
              ? 'border-rose-400 bg-rose-500/10 text-rose-500'
              : isDark
                ? 'border-slate-600 bg-slate-800 text-slate-300'
                : 'border-slate-300 bg-white text-slate-600'
              }`}
          >
            {item}
          </button>
        ))}
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        {list.map((coupon) => <CouponCard key={coupon.id} coupon={coupon} isDark={isDark} />)}
      </div>
    </motion.section>
  );
}

export default CouponsPanel;
