import { useMemo, useState } from 'react';

function buildPath(data, width, height) {
  if (!data.length) return '';
  const max = Math.max(...data.map((d) => d.value), 1);
  const min = Math.min(...data.map((d) => d.value), 0);
  const range = max - min || 1;

  return data
    .map((point, index) => {
      const x = (index / (data.length - 1 || 1)) * width;
      const y = height - ((point.value - min) / range) * height;
      return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(' ');
}

function nearestIndex(target, total) {
  if (total <= 1) return 0;
  const idx = Math.round(target * (total - 1));
  return Math.min(total - 1, Math.max(0, idx));
}

function LineTrendChart({ title, data = [] }) {
  const width = 640;
  const height = 240;
  const [hoverIndex, setHoverIndex] = useState(null);

  const points = useMemo(() => data.map((item) => ({ date: item.date, value: Number(item.value || 0) })), [data]);
  const path = useMemo(() => buildPath(points, width, height), [points]);

  const tooltipItem = hoverIndex != null ? points[hoverIndex] : null;

  return (
    <section className="admin-chart-card">
      <header>
        <h3>{title}</h3>
      </header>

      <div
        className="line-chart-wrap"
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect();
          const ratio = (event.clientX - rect.left) / Math.max(rect.width, 1);
          setHoverIndex(nearestIndex(ratio, points.length));
        }}
        onMouseLeave={() => setHoverIndex(null)}
      >
        <svg viewBox={`0 0 ${width} ${height}`} className="line-chart-svg" preserveAspectRatio="none">
          <defs>
            <linearGradient id={`fill-${title}`} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="rgba(48,122,251,0.32)" />
              <stop offset="100%" stopColor="rgba(48,122,251,0.03)" />
            </linearGradient>
          </defs>
          <path d={path} className="line-stroke" />
          {hoverIndex != null && points[hoverIndex] ? (
            <circle
              cx={(hoverIndex / Math.max(points.length - 1, 1)) * width}
              cy={height - ((points[hoverIndex].value - Math.min(...points.map((d) => d.value), 0)) / (Math.max(...points.map((d) => d.value), 1) - Math.min(...points.map((d) => d.value), 0) || 1)) * height}
              r="4.5"
              className="line-point"
            />
          ) : null}
        </svg>

        {tooltipItem ? (
          <div className="chart-tooltip">
            <strong>{new Intl.NumberFormat('en-IN').format(tooltipItem.value)}</strong>
            <span>{tooltipItem.date}</span>
          </div>
        ) : null}
      </div>
    </section>
  );
}

export default LineTrendChart;
