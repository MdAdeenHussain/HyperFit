import { motion } from 'framer-motion';

function PlaceholderPanel({ title, description, isDark }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <h3 className="m-0 text-xl font-semibold">{title}</h3>
      <p className={`m-0 mt-2 max-w-2xl text-sm ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>{description}</p>
      <div className={`mt-5 rounded-xl border p-4 text-sm ${isDark ? 'border-slate-700 bg-slate-800 text-slate-300' : 'border-slate-200 bg-slate-50 text-slate-600'}`}>
        This section is ready for backend integration when APIs are available.
      </div>
    </motion.section>
  );
}

export default PlaceholderPanel;
