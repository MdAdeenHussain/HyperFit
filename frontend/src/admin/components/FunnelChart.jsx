function FunnelChart({ title, items = [] }) {
  const maxValue = Math.max(...items.map((item) => Number(item.value || 0)), 1);

  return (
    <section className="admin-chart-card">
      <header>
        <h3>{title}</h3>
      </header>
      <div className="funnel-list">
        {items.map((item) => {
          const width = Math.max(8, Math.round((Number(item.value || 0) / maxValue) * 100));
          return (
            <div className="funnel-row" key={item.step}>
              <span>{item.step}</span>
              <div className="funnel-track">
                <div className="funnel-bar" style={{ width: `${width}%` }} />
              </div>
              <strong>{new Intl.NumberFormat('en-IN').format(Number(item.value || 0))}</strong>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default FunnelChart;
