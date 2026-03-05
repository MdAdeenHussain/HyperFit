import { AnimatePresence, motion } from 'framer-motion';

const ICONS = {
  overview: 'OV',
  orders: 'OR',
  coupon: 'CP',
  credit: 'CR',
  wallet: 'WL',
  profile: 'PR',
  card: 'CD',
  upi: 'UP',
  address: 'AD',
  theme: 'TH',
  delete: 'DL',
  logout: 'LO',
  terms: 'TR',
  privacy: 'PV'
};

function SidebarMenu({ groups, activeTab, onSelect, userName, isDark }) {
  return (
    <div className="flex h-full flex-col">
      <div className={`border-b px-5 py-5 ${isDark ? 'border-slate-700' : 'border-slate-200'}`}>
        <h2 className="m-0 text-xl font-semibold">Account</h2>
        <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{userName}</p>
      </div>

      <nav className="flex-1 overflow-y-auto px-4 py-3">
        {groups.map((group) => (
          <section key={group.title || 'primary'} className="mb-4">
            {group.title ? <p className={`m-0 mb-2 px-2 text-xs uppercase tracking-[0.14em] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{group.title}</p> : null}
            <div className={`space-y-1 rounded-xl border p-1 ${isDark ? 'border-slate-800 bg-slate-900/60' : 'border-slate-100 bg-slate-50'}`}>
              {group.items.map((item) => {
                const active = activeTab === item.key;
                return (
                  <motion.button
                    whileHover={{ x: 2 }}
                    key={item.key}
                    type="button"
                    onClick={() => onSelect(item.key)}
                    className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm font-medium transition ${
                      active
                        ? isDark
                          ? 'bg-slate-700 text-white shadow-[0_0_0_1px_rgba(244,63,94,0.35),0_0_18px_rgba(244,63,94,0.24)]'
                          : 'bg-white text-slate-900 shadow-[0_0_0_1px_rgba(244,63,94,0.3),0_8px_18px_rgba(244,63,94,0.2)]'
                        : isDark
                          ? 'text-slate-300 hover:bg-slate-800'
                          : 'text-slate-600 hover:bg-white'
                    }`}
                  >
                    <span className="w-4 text-center text-[10px] font-bold">{ICONS[item.icon] || '--'}</span>
                    <span>{item.label}</span>
                  </motion.button>
                );
              })}
            </div>
          </section>
        ))}
      </nav>
    </div>
  );
}

function AccountSidebar({ groups, activeTab, onSelect, userName, openMobile, onCloseMobile, isDark }) {
  return (
    <>
      <aside className={`hidden h-[calc(100vh-9.8rem)] overflow-hidden rounded-2xl border lg:block ${isDark ? 'border-slate-700 bg-slate-950' : 'border-slate-200 bg-slate-100/80'}`}>
        <SidebarMenu groups={groups} activeTab={activeTab} onSelect={onSelect} userName={userName} isDark={isDark} />
      </aside>

      <AnimatePresence>
        {openMobile ? (
          <>
            <motion.button
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              type="button"
              className="fixed inset-0 z-40 bg-black/45 lg:hidden"
              onClick={onCloseMobile}
            />
            <motion.aside
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 26, stiffness: 240 }}
              className={`fixed left-0 top-0 z-50 h-full w-[86vw] max-w-[320px] border-r lg:hidden ${isDark ? 'border-slate-700 bg-slate-950' : 'border-slate-200 bg-slate-100'}`}
            >
              <div className="flex items-center justify-end p-3">
                <button
                  type="button"
                  onClick={onCloseMobile}
                  className={`rounded-full border px-3 py-1 text-sm ${isDark ? 'border-slate-700 bg-slate-900 text-slate-200' : 'border-slate-300 bg-white text-slate-700'}`}
                >
                  Close
                </button>
              </div>
              <SidebarMenu
                groups={groups}
                activeTab={activeTab}
                onSelect={(tab) => {
                  onSelect(tab);
                  onCloseMobile();
                }}
                userName={userName}
                isDark={isDark}
              />
            </motion.aside>
          </>
        ) : null}
      </AnimatePresence>
    </>
  );
}

export default AccountSidebar;
