import { motion } from 'framer-motion';

const OPTIONS = [
  { key: 'light', title: 'Light Mode', subtitle: 'Clean and bright performance workspace.' },
  { key: 'dark', title: 'Dark Mode', subtitle: 'Low-glare mode with premium contrast.' }
];

function ThemeSelector({ theme, setTheme, isDark }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <h3 className="m-0 text-xl font-semibold">Theme</h3>
      <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Choose how HyperFit looks across all pages.</p>

      <div className="mt-5 grid gap-4 md:grid-cols-2">
        {OPTIONS.map((option) => {
          const active = theme === option.key;
          const cardModeClasses = option.key === 'dark'
            ? 'border-slate-700 bg-slate-900 text-slate-100'
            : 'border-slate-200 bg-white text-slate-900';

          return (
            <motion.button
              whileHover={{ y: -4 }}
              key={option.key}
              type="button"
              onClick={() => setTheme(option.key)}
              className={`rounded-2xl border p-4 text-left ${active
                ? option.key === 'dark'
                  ? 'border-rose-300 bg-slate-900 shadow-[0_0_0_1px_rgba(244,63,94,0.3),0_0_20px_rgba(244,63,94,0.25)]'
                  : 'border-rose-300 bg-white shadow-[0_0_0_1px_rgba(244,63,94,0.25),0_10px_20px_rgba(244,63,94,0.15)]'
                : cardModeClasses
                }`}
            >
              <div className={`mb-3 h-24 w-full rounded-xl border p-2 ${option.key === 'dark' ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}>
                <div className={`h-4 w-20 rounded-full ${option.key === 'dark' ? 'bg-slate-700' : 'bg-slate-200'}`} />
                <div className={`mt-2 h-3 w-32 rounded-full ${option.key === 'dark' ? 'bg-slate-700' : 'bg-slate-200'}`} />
                <div className={`mt-3 h-8 rounded-lg ${option.key === 'dark' ? 'bg-slate-800' : 'bg-slate-100'}`} />
              </div>
              <h4 className="m-0 text-base font-semibold">{option.title}</h4>
              <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{option.subtitle}</p>
            </motion.button>
          );
        })}
      </div>
    </motion.section>
  );
}

export default ThemeSelector;
