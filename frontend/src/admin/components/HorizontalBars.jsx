function HorizontalBars({ title, items = [], labelKey = 'source', valueKey = 'value' }) {
  const max = Math.max(...items.map((item) => Number(item[valueKey] || 0)), 1);

  return (
    <section className="admin-chart-card">
      <header>
        <h3>{title}</h3>
      </header>
      <div className="hbars-list">
        {items.map((item) => {
          const percent = Math.round((Number(item[valueKey] || 0) / max) * 100);
          return (
            <div className="hbar-row" key={item[labelKey]}>
              <div>
                <span>{item[labelKey]}</span>
                <small>{item[valueKey]}%</small>
              </div>
              <div className="hbar-track">
                <div className="hbar-fill" style={{ width: `${percent}%` }} />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default HorizontalBars;
