function AdminSkeleton({ rows = 6 }) {
  return (
    <div className="admin-skeleton">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="admin-skeleton-row" />
      ))}
    </div>
  );
}

export default AdminSkeleton;
