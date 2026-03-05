function SkeletonLoader({ rows = 3, variant = 'rows' }) {
  if (variant === 'cards') {
    return (
      <div className="skeleton-card-grid" aria-label="Loading products">
        {Array.from({ length: rows }).map((_, index) => (
          <article key={index} className="skeleton-product-card">
            <div className="skeleton-product-image" />
            <div className="skeleton-row" />
            <div className="skeleton-row short" />
          </article>
        ))}
      </div>
    );
  }

  return (
    <div className="skeleton-wrap" aria-label="Loading content">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton-row" />
      ))}
    </div>
  );
}

export default SkeletonLoader;
