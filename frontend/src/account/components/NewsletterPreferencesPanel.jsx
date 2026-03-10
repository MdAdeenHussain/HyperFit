import { motion } from 'framer-motion';

function NewsletterPreferencesPanel({ subscribed, saving, message, status, onToggle, isDark }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h3 className="m-0 text-xl font-semibold">Newsletter Subscription</h3>
          <p className={`m-0 mt-2 max-w-2xl text-sm ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
            Receive promotional emails, early drop alerts, and member-only offers. Changes are saved immediately.
          </p>
        </div>

        <label className={`flex min-w-[220px] items-center justify-between gap-4 rounded-2xl border px-4 py-3 ${isDark ? 'border-slate-700 bg-slate-800' : 'border-slate-200 bg-slate-50'}`}>
          <div>
            <strong className="block text-sm">Receive promotional emails</strong>
            <small className={isDark ? 'text-slate-400' : 'text-slate-500'}>{subscribed ? 'Subscribed' : 'Unsubscribed'}</small>
          </div>
          <input
            type="checkbox"
            checked={subscribed}
            disabled={saving}
            onChange={(event) => onToggle(event.target.checked)}
            aria-label="Receive promotional emails"
            className="h-5 w-5 accent-rose-500"
          />
        </label>
      </div>

      {message ? (
        <p className={`m-0 mt-4 text-sm ${status === 'error' ? 'text-rose-500' : isDark ? 'text-emerald-300' : 'text-emerald-600'}`}>
          {message}
        </p>
      ) : null}
    </motion.section>
  );
}

export default NewsletterPreferencesPanel;
