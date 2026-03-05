import { motion } from 'framer-motion';

function AccountHeader({ userName, activeLabel, onOpenMenu, isDark }) {
  return (
    <motion.header
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28 }}
      className={`rounded-2xl border px-4 py-4 sm:px-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className={`text-xs uppercase tracking-[0.18em] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Account Center</p>
          <h1 className="m-0 mt-1 text-2xl font-bold">{activeLabel}</h1>
          <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>{userName}</p>
        </div>

        <button
          type="button"
          onClick={onOpenMenu}
          className={`lg:hidden rounded-full border px-4 py-2 text-sm font-semibold ${isDark ? 'border-slate-700 bg-slate-800 text-slate-100' : 'border-slate-300 bg-slate-50 text-slate-700'}`}
        >
          Menu
        </button>
      </div>
    </motion.header>
  );
}

export default AccountHeader;
