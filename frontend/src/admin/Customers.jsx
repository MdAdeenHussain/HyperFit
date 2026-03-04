import { useEffect, useState } from 'react';
import { API_BASE_URL } from '../utils/constants';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

function Customers() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [profile, setProfile] = useState(null);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await adminService.getCustomers({ q: search, status });
      setRows(data.items || []);
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load customers');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [search, status]); // eslint-disable-line react-hooks/exhaustive-deps

  const download = async (url, filename) => {
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
          <h1>Customer Management</h1>
          <p>View profiles, order history, total spent and account controls.</p>
        </div>
        <button className="admin-btn" onClick={() => download(`${API_BASE_URL}/admin/export/customers.csv`, 'customers.csv')}>Export CSV</button>
      </section>

      <section className="admin-filter-bar">
        <input type="search" placeholder="Search customers" value={search} onChange={(e) => setSearch(e.target.value)} />
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All</option>
          <option value="active">Active</option>
          <option value="blocked">Blocked</option>
        </select>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}
      {loading ? <AdminSkeleton rows={8} /> : null}

      {!loading ? (
        <section className="admin-table-card">
          <div className="admin-table-scroll">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Customer</th>
                  <th>Email</th>
                  <th>Phone</th>
                  <th>Orders</th>
                  <th>Total Spent</th>
                  <th>Last Order</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td>{row.name}</td>
                    <td>{row.email}</td>
                    <td>{row.phone || '-'}</td>
                    <td>{row.orders}</td>
                    <td>{new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(row.total_spent || 0)}</td>
                    <td>{row.last_order ? new Date(row.last_order).toLocaleDateString() : '-'}</td>
                    <td>
                      <span className={row.is_active ? 'pill success' : 'pill danger'}>{row.is_active ? 'Active' : 'Blocked'}</span>
                    </td>
                    <td>
                      <div className="row-actions-inline">
                        <button className="ghost" onClick={async () => {
                          const { data } = await adminService.getCustomerProfile(row.id);
                          setProfile(data);
                        }}>Profile</button>
                        {!row.is_admin ? (
                          <button className="ghost" onClick={() => adminService.toggleCustomerBlock(row.id, row.is_active).then(load)}>
                            {row.is_active ? 'Block' : 'Unblock'}
                          </button>
                        ) : null}
                        <button className="ghost" onClick={() => download(`${API_BASE_URL}/admin/customers/${row.id}/orders/export.csv`, `customer-${row.id}-orders.csv`)}>Orders CSV</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {profile ? (
        <section className="admin-profile-modal" onClick={() => setProfile(null)}>
          <article onClick={(e) => e.stopPropagation()}>
            <header>
              <h3>{profile.name}</h3>
              <button className="ghost" onClick={() => setProfile(null)}>Close</button>
            </header>
            <p>{profile.email} {profile.phone ? `• ${profile.phone}` : ''}</p>
            <strong>Total spent: {new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(profile.total_spent || 0)}</strong>

            <div className="mini-order-list">
              {(profile.orders || []).slice(0, 10).map((order) => (
                <div key={order.order_number}>
                  <p>{order.order_number}</p>
                  <small>{order.status} • {new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(order.amount || 0)}</small>
                </div>
              ))}
            </div>
          </article>
        </section>
      ) : null}
    </div>
  );
}

export default Customers;
