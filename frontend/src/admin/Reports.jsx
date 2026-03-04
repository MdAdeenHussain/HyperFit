import { useEffect, useState } from 'react';
import { API_BASE_URL } from '../utils/constants';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

const REPORT_TYPES = [
  { key: 'revenue', label: 'Revenue Report' },
  { key: 'products', label: 'Product Sales Report' },
  { key: 'customers', label: 'Customer Acquisition' },
  { key: 'marketing', label: 'Marketing Performance' }
];

function Reports() {
  const [range, setRange] = useState('30d');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await adminService.getReportSummary({ range });
      setData(response.data);
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load reports');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [range]); // eslint-disable-line react-hooks/exhaustive-deps

  const download = async (type, ext) => {
    const endpoint = ext === 'csv' ? 'csv' : 'pdf';
    const response = await fetch(`${API_BASE_URL}/admin/reports/export.${endpoint}?type=${type}`, {
      headers: {
        Authorization: `Bearer ${localStorage.getItem('hf_access_token') || ''}`,
        'X-CSRF-Token': localStorage.getItem('hf_csrf_token') || ''
      }
    });
    const blob = await response.blob();
    const href = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = href;
    a.download = `${type}-report.${ext}`;
    a.click();
    URL.revokeObjectURL(href);
  };

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>Reports & Analytics</h1>
          <p>Generate advanced reports and export in CSV or PDF format.</p>
        </div>
        <select value={range} onChange={(e) => setRange(e.target.value)}>
          <option value="today">Today</option>
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
          <option value="year">This Year</option>
        </select>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}
      {loading ? <AdminSkeleton rows={6} /> : null}

      {!loading && data ? (
        <>
          <section className="metrics-grid">
            <article className="admin-metric-card">
              <p>Total Revenue</p>
              <strong>{new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(data.revenue_report?.total_revenue || 0)}</strong>
            </article>
            <article className="admin-metric-card">
              <p>Total Orders</p>
              <strong>{data.revenue_report?.total_orders || 0}</strong>
            </article>
            <article className="admin-metric-card">
              <p>Average Order Value</p>
              <strong>{new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(data.revenue_report?.average_order_value || 0)}</strong>
            </article>
            <article className="admin-metric-card">
              <p>New Customers</p>
              <strong>{data.customer_acquisition?.new_customers || 0}</strong>
            </article>
          </section>

          <section className="admin-dual-grid">
            <article className="admin-panel-card">
              <header><h3>Top Product Sales</h3></header>
              <ul className="report-list">
                {(data.product_sales_report || []).slice(0, 8).map((item) => (
                  <li key={item.product_name}><span>{item.product_name}</span><strong>{item.units_sold}</strong></li>
                ))}
              </ul>
            </article>

            <article className="admin-panel-card">
              <header><h3>Marketing Performance</h3></header>
              <ul className="report-list">
                <li><span>Email Open Rate</span><strong>{data.marketing_performance?.email_open_rate || 0}%</strong></li>
                <li><span>Email Click Rate</span><strong>{data.marketing_performance?.email_click_rate || 0}%</strong></li>
                <li><span>Acquisition Rate</span><strong>{data.customer_acquisition?.acquisition_rate_estimate || 0}%</strong></li>
              </ul>
            </article>
          </section>

          <section className="admin-panel-card">
            <header><h3>Export Reports</h3></header>
            <div className="export-grid">
              {REPORT_TYPES.map((item) => (
                <article key={item.key} className="export-card">
                  <strong>{item.label}</strong>
                  <div className="row-actions-inline">
                    <button className="ghost" onClick={() => download(item.key, 'csv')}>CSV</button>
                    <button className="ghost" onClick={() => download(item.key, 'pdf')}>PDF</button>
                  </div>
                </article>
              ))}
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}

export default Reports;
