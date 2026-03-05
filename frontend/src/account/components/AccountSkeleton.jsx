function AccountSkeleton({ isDark }) {
  return (
    <section className={`rounded-2xl border p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}>
      <div className="space-y-3">
        {Array.from({ length: 8 }).map((_, index) => (
          <div
            key={index}
            className={`h-5 animate-pulse rounded-lg ${isDark ? 'bg-slate-700' : 'bg-slate-200'}`}
            style={{ width: `${Math.max(40, 95 - index * 5)}%` }}
          />
        ))}
      </div>
    </section>
  );
}

export default AccountSkeleton;
