import { useEffect, useMemo, useState } from 'react';
import { API_BASE_URL } from '../utils/constants';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

const STATUSES = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'];
const PAYMENT_STATUSES = ['pending', 'paid', 'failed', 'refunded'];

function Orders() {
  const [rows, setRows] = useState([]);
  const [meta, setMeta] = useState({ page: 1, pages: 1, total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [filters, setFilters] = useState({ status: '', payment_status: '' });

  const params = useMemo(() => ({ page: meta.page, q: query, ...filters }), [meta.page, query, filters]);

  const loadOrders = async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await adminService.getOrders(params);
      setRows(data.items || []);
      setMeta((prev) => ({ ...prev, ...(data.meta || {}) }));
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load orders');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOrders();
  }, [params.page, params.q, params.status, params.payment_status]); // eslint-disable-line react-hooks/exhaustive-deps

  const updateOrder = async (orderNumber, payload) => {
    await adminService.updateOrder(orderNumber, payload);
    loadOrders();
  };

  const downloadAdminFile = async (url, filename) => {
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${localStorage.getItem('hf_access_token') || ''}`,
        'X-CSRF-Token': localStorage.getItem('hf_csrf_token') || ''
      }
    });
    const blob = await response.blob();
    const href = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = href;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(href);
  };

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>Order Management</h1>
          <p>Search, filter, update, cancel, refund and export orders.</p>
        </div>
        <button
          onClick={() => downloadAdminFile(`${API_BASE_URL}/admin/orders/export.csv`, 'orders.csv')}
          className="admin-btn"
        >
          Download CSV
        </button>
      </section>

      <section className="admin-filter-bar">
        <input
          type="search"
          placeholder="Search by order id, customer, email"
          value={query}
          onChange={(e) => {
            setMeta((prev) => ({ ...prev, page: 1 }));
            setQuery(e.target.value);
          }}
        />

        <select
          value={filters.status}
          onChange={(e) => {
            setMeta((prev) => ({ ...prev, page: 1 }));
            setFilters((prev) => ({ ...prev, status: e.target.value }));
          }}
        >
          <option value="">All statuses</option>
          {STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
        </select>

        <select
          value={filters.payment_status}
          onChange={(e) => {
            setMeta((prev) => ({ ...prev, page: 1 }));
            setFilters((prev) => ({ ...prev, payment_status: e.target.value }));
          }}
        >
          <option value="">All payment states</option>
          {PAYMENT_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
        </select>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}
      {loading ? <AdminSkeleton rows={8} /> : null}

      {!loading ? (
        <section className="admin-table-card">
          <div className="table-header-row">
            <strong>{meta.total} Orders</strong>
            <span>Page {meta.page} of {meta.pages}</span>
          </div>
          <div className="admin-table-scroll">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Order ID</th>
                  <th>Customer</th>
                  <th>Products</th>
                  <th>Payment</th>
                  <th>Order</th>
                  <th>Amount</th>
                  <th>Date</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.order_number}>
                    <td>{row.order_number}</td>
                    <td>
                      <strong>{row.customer}</strong>
                      <small>{row.customer_email}</small>
                    </td>
                    <td>{(row.products || []).slice(0, 2).map((p) => `${p.name} x${p.quantity}`).join(', ')}</td>
                    <td>
                      <select
                        value={row.payment_status}
                        onChange={(e) => updateOrder(row.order_number, { payment_status: e.target.value })}
                      >
                        {PAYMENT_STATUSES.map((item) => <option key={item} value={item}>{item}</option>)}
                      </select>
                    </td>
                    <td>
                      <select
                        value={row.status}
                        onChange={(e) => updateOrder(row.order_number, { status: e.target.value })}
                      >
                        {STATUSES.map((item) => <option key={item} value={item}>{item}</option>)}
                      </select>
                    </td>
                    <td>{new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(row.amount || 0)}</td>
                    <td>{new Date(row.created_at).toLocaleDateString()}</td>
                    <td>
                      <div className="row-actions-inline">
                        <button onClick={() => adminService.cancelOrder(row.order_number).then(loadOrders)} className="ghost danger">Cancel</button>
                        <button onClick={() => adminService.refundOrder(row.order_number).then(loadOrders)} className="ghost">Refund</button>
                        <button
                          onClick={() => downloadAdminFile(`${API_BASE_URL}/admin/orders/${row.order_number}/invoice`, `${row.order_number}-invoice.pdf`)}
                          className="ghost"
                        >
                          Invoice
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      <section className="pagination-row">
        <button disabled={meta.page <= 1} onClick={() => setMeta((prev) => ({ ...prev, page: prev.page - 1 }))}>Previous</button>
        <button disabled={meta.page >= meta.pages} onClick={() => setMeta((prev) => ({ ...prev, page: prev.page + 1 }))}>Next</button>
      </section>
    </div>
  );
}

export default Orders;
