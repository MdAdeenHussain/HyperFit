import Sparkline from './Sparkline';

function formatMetric(value, format) {
  if (format === 'currency') {
    return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(Number(value || 0));
  }
  if (format === 'percent') {
    return `${Number(value || 0).toFixed(2)}%`;
  }
  return new Intl.NumberFormat('en-IN').format(Number(value || 0));
}

function MetricCard({ item }) {
  const delta = Number(item.delta || 0);
  const up = delta >= 0;

  return (
    <article className="admin-metric-card">
      <header>
        <p>{item.label}</p>
      </header>
      <strong>{formatMetric(item.value, item.format)}</strong>
      <div className="metric-foot">
        <span className={up ? 'delta-up' : 'delta-down'}>{up ? '+' : ''}{delta}% this period</span>
        <Sparkline values={item.sparkline} positive={up} />
      </div>
    </article>
  );
}

export default MetricCard;
