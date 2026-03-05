import { motion } from 'framer-motion';

function CouponCard({ coupon, isDark }) {
  return (
    <motion.article
      whileHover={{ y: -4 }}
      transition={{ duration: 0.2 }}
      className={`grid grid-cols-[112px_1fr] overflow-hidden rounded-2xl border ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <img src={coupon.image} alt={coupon.title} loading="lazy" className="h-full w-full object-cover" />

      <div className="p-4">
        <h4 className="m-0 text-xl font-semibold">{coupon.title}</h4>
        <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>{coupon.minimumText}</p>
        <p className={`m-0 mt-2 text-xs uppercase tracking-[0.1em] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Code: {coupon.code}</p>
        <p className={`m-0 mt-1 text-sm font-semibold ${isDark ? 'text-slate-100' : 'text-slate-700'}`}>Expiry: {coupon.expiryLabel}</p>
        <button
          type="button"
          className="mt-3 rounded-full bg-rose-500 px-4 py-2 text-xs font-semibold uppercase tracking-[0.08em] text-white transition hover:bg-rose-600"
        >
          View Products
        </button>
      </div>
    </motion.article>
  );
}

export default CouponCard;
