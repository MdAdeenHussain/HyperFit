function SkeletonLoader({ rows = 3 }) {
  return (
    <div className="skeleton-wrap" aria-label="Loading content">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton-row" />
      ))}
    </div>
  );
}

export default SkeletonLoader;
