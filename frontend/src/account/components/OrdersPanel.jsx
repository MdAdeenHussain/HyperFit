import { motion } from 'framer-motion';
import { inr } from '../../utils/helpers';

function OrdersPanel({ orders = [], onInvoice, isDark }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <h3 className="m-0 text-xl font-semibold">Orders & Returns</h3>
      <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Track your shipments and download invoices.</p>

      <div className="mt-4 space-y-3">
        {orders.length ? orders.map((order) => (
          <article key={order.order_number} className={`rounded-xl border p-4 ${isDark ? 'border-slate-700 bg-slate-800/50' : 'border-slate-200 bg-slate-50'}`}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="m-0 text-sm font-semibold uppercase tracking-[0.1em]">{order.order_number}</p>
                <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Ordered: {new Date(order.ordered_date).toLocaleDateString()}</p>
                <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Expected delivery: {order.expected_delivery ? new Date(order.expected_delivery).toLocaleDateString() : 'TBD'}</p>
              </div>

              <div className="flex items-center gap-2">
                <span className={`rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.09em] ${order.status === 'delivered' ? 'bg-emerald-500/15 text-emerald-400' : order.status === 'cancelled' ? 'bg-rose-500/15 text-rose-400' : isDark ? 'bg-slate-700 text-slate-200' : 'bg-slate-200 text-slate-700'}`}>
                  {order.status}
                </span>
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
        )) : <p className={`${isDark ? 'text-slate-400' : 'text-slate-500'}`}>No orders available.</p>}
      </div>
    </motion.section>
  );
}

export default OrdersPanel;
