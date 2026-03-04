import { useEffect, useState } from 'react';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

function Inventory() {
  const [data, setData] = useState({ items: [], summary: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await adminService.getInventory();
      setData(response.data || { items: [], summary: {} });
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load inventory');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>Inventory Management</h1>
          <p>Track stock by product variant, low stock alerts and out-of-stock statuses.</p>
        </div>
      </section>

      <section className="metrics-grid inventory-metrics">
        <article className="admin-metric-card">
          <p>Low Stock Alerts</p>
          <strong>{data.summary.low_stock_alerts || 0}</strong>
        </article>
        <article className="admin-metric-card">
          <p>Out of Stock</p>
          <strong>{data.summary.out_of_stock || 0}</strong>
        </article>
        <article className="admin-metric-card">
          <p>Total Variants</p>
          <strong>{data.summary.total_variants || 0}</strong>
        </article>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}
      {loading ? <AdminSkeleton rows={8} /> : null}

      {!loading ? (
        <section className="admin-table-card">
          <div className="admin-table-scroll">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Variant</th>
                  <th>Stock Quantity</th>
                  <th>Low Stock Warning</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {(data.items || []).map((row) => (
                  <tr key={row.id}>
                    <td>{row.product}</td>
                    <td>{row.variant}</td>
                    <td>{row.stock_quantity}</td>
                    <td>{row.low_stock_warning ? 'Yes' : 'No'}</td>
                    <td>
                      <span className={row.status === 'In Stock' ? 'pill success' : row.status === 'Low Stock' ? 'pill warning' : 'pill danger'}>
                        {row.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </div>
  );
}

export default Inventory;
