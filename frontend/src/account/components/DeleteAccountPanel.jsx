import { useState } from 'react';
import { motion } from 'framer-motion';

function DeleteAccountPanel({ onKeepAccount, onDelete, isDark }) {
  const [agreed, setAgreed] = useState(false);

  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <div className="mx-auto max-w-4xl">
        <div className={`mx-auto mb-5 flex h-36 w-36 items-center justify-center rounded-full text-5xl font-bold ${isDark ? 'bg-rose-900/35' : 'bg-rose-100'}`}>!</div>

        <h3 className="m-0 text-2xl font-semibold">Are you sure you want to delete your account?</h3>
        <ul className={`mt-4 space-y-2 pl-5 text-sm leading-6 ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
          <li>Loss of order history and tracking records</li>
          <li>Loss of store credits, wallet and active coupons</li>
          <li>Loss of saved addresses and payment preferences</li>
          <li>Security archival may retain limited legal records</li>
        </ul>

        <label className="mt-4 flex items-start gap-2 text-sm font-medium">
          <input type="checkbox" checked={agreed} onChange={(event) => setAgreed(event.target.checked)} className="mt-1" />
          <span>I agree to the terms and conditions.</span>
        </label>

        <div className="mt-5 flex flex-wrap gap-3">
          <button
            type="button"
            onClick={onDelete}
            disabled={!agreed}
            className="rounded-full border border-rose-400 px-5 py-2 text-sm font-semibold uppercase tracking-[0.08em] text-rose-500 transition hover:bg-rose-500/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Delete Anyway
          </button>
          <button
            type="button"
            onClick={onKeepAccount}
            className="rounded-full bg-rose-500 px-5 py-2 text-sm font-semibold uppercase tracking-[0.08em] text-white transition hover:bg-rose-600"
          >
            Keep Account
          </button>
        </div>
      </div>
    </motion.section>
  );
}

export default DeleteAccountPanel;
