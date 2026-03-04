function Sparkline({ values = [], positive = true }) {
  const width = 96;
  const height = 30;
  const points = values.length ? values : [0, 0, 0, 0, 0, 0, 0, 0];
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = max - min || 1;

  const polyline = points
    .map((value, index) => {
      const x = (index / (points.length - 1 || 1)) * width;
      const y = height - ((value - min) / range) * height;
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <svg className="admin-sparkline" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
      <polyline points={polyline} className={positive ? 'sparkline-positive' : 'sparkline-negative'} />
    </svg>
  );
}

export default Sparkline;
