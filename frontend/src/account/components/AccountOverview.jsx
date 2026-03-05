import { motion } from 'framer-motion';
import { inr } from '../../utils/helpers';

function AccountOverview({ stats, recentOrders = [], onInvoice, isDark }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <h3 className="m-0 text-xl font-semibold">Overview</h3>
      <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Your HyperFit account at a glance.</p>

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {stats.map((item) => (
          <motion.article
            whileHover={{ y: -3 }}
            transition={{ duration: 0.2 }}
            key={item.label}
            className={`rounded-xl border px-3 py-4 ${isDark ? 'border-slate-700 bg-slate-800/60' : 'border-slate-200 bg-slate-50'}`}
          >
            <p className={`m-0 text-xs uppercase tracking-[0.12em] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{item.label}</p>
            <strong className="mt-2 block text-2xl">{item.value}</strong>
          </motion.article>
        ))}
      </div>

      <div className="mt-6">
        <h4 className="m-0 text-base font-semibold">Recent Orders</h4>
        <div className="mt-3 space-y-3">
          {recentOrders.length ? recentOrders.map((order) => (
            <article key={order.order_number} className={`rounded-xl border p-4 ${isDark ? 'border-slate-700 bg-slate-800/50' : 'border-slate-200 bg-white'}`}>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="m-0 font-semibold">{order.order_number}</p>
                  <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{new Date(order.ordered_date).toLocaleDateString()} · {order.status}</p>
                </div>
                <div className="flex items-center gap-3">
                  <strong>{inr(order.price)}</strong>
                  <button
                    type="button"
                    onClick={() => onInvoice(order.order_number)}
                    className={`rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.08em] ${isDark ? 'border-slate-600 bg-slate-900 text-slate-100' : 'border-slate-300 bg-white text-slate-700'}`}
                  >
                    Invoice
                  </button>
                </div>
              </div>
            </article>
          )) : (
            <p className={`${isDark ? 'text-slate-400' : 'text-slate-500'}`}>No orders found yet.</p>
          )}
        </div>
      </div>
    </motion.section>
  );
}

export default AccountOverview;
