import { useEffect, useMemo, useState } from 'react';
import adminService from '../services/adminService';
import MetricCard from './components/MetricCard';
import LineTrendChart from './components/LineTrendChart';
import FunnelChart from './components/FunnelChart';
import HorizontalBars from './components/HorizontalBars';
import AdminSkeleton from './components/AdminSkeleton';

const RANGE_OPTIONS = [
  { key: 'today', label: 'Today' },
  { key: '7d', label: 'Last 7 Days' },
  { key: '30d', label: 'Last 30 Days' },
  { key: 'year', label: 'This Year' },
  { key: 'custom', label: 'Custom Range' }
];

function compactCurrency(value) {
  return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', notation: 'compact', maximumFractionDigits: 1 }).format(Number(value || 0));
}

function MiniWorldMap({ countries = [] }) {
  const max = Math.max(...countries.map((item) => Number(item.orders || 0)), 1);
  return (
    <div className="world-map-card">
      <svg viewBox="0 0 480 220" className="world-map-svg" aria-hidden="true">
        <path d="M35 87l42-28 40 12 30-10 34 12 24-8 38 18 40-7 44 21 17 25-44 16-63 4-67 22-38-12-34 9-37-20-18-24z" className="continent-shape" />
        <path d="M308 53l35-14 41 10 26 19 4 30-29 18-31-8-31-18-12-20z" className="continent-shape" />
        <path d="M166 143l26 10 14 34-21 18-29-12-9-23z" className="continent-shape" />
        {countries.slice(0, 6).map((country, idx) => {
          const intensity = Number(country.orders || 0) / max;
          return (
            <circle
              key={`${country.country}-${idx}`}
              cx={70 + idx * 62}
              cy={100 + ((idx % 2) * 28)}
              r={4 + intensity * 6}
              style={{ opacity: 0.45 + intensity * 0.5 }}
              className="country-point"
            />
          );
        })}
      </svg>
      <ul>
        {countries.slice(0, 5).map((country) => (
          <li key={country.country}>
            <span>{country.country}</span>
            <strong>{country.orders}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Dashboard() {
  const [range, setRange] = useState('30d');
  const [customRange, setCustomRange] = useState({ start: '', end: '' });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [data, setData] = useState(null);

  const params = useMemo(() => {
    if (range === 'custom') {
      return { range, start: customRange.start, end: customRange.end };
    }
    return { range };
  }, [range, customRange]);

  useEffect(() => {
    let mounted = true;
    async function loadDashboard() {
      setLoading(true);
      setError('');
      try {
        const response = await adminService.getDashboard(params);
        if (mounted) setData(response.data);
      } catch (err) {
        if (mounted) setError(err?.response?.data?.error || err?.message || 'Unable to fetch dashboard data');
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadDashboard();
    return () => {
      mounted = false;
    };
  }, [params]);

  return (
    <div className="admin-page dashboard-page">
      <section className="page-head-row">
        <div>
          <h1>Dashboard Overview</h1>
          <p>Revenue, orders, customer behavior and live platform activity in one place.</p>
        </div>
        <div className="range-controls">
          {RANGE_OPTIONS.map((item) => (
            <button
              key={item.key}
              className={range === item.key ? 'active' : ''}
              onClick={() => setRange(item.key)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </section>

      {range === 'custom' ? (
        <section className="custom-range-row">
          <label>
            Start
            <input type="date" value={customRange.start} onChange={(e) => setCustomRange((prev) => ({ ...prev, start: e.target.value }))} />
          </label>
          <label>
            End
            <input type="date" value={customRange.end} onChange={(e) => setCustomRange((prev) => ({ ...prev, end: e.target.value }))} />
          </label>
        </section>
      ) : null}

      {error ? <div className="admin-error">{error}</div> : null}
      {loading ? <AdminSkeleton rows={10} /> : null}

      {!loading && data ? (
        <>
          <section className="metrics-grid">
            {(data.metrics || []).map((item) => (
              <MetricCard key={item.key} item={item} />
            ))}
          </section>

          <section className="dashboard-split-grid">
            <LineTrendChart title="Revenue Over Time" data={data.sales_analytics?.revenue_over_time || []} />
            <LineTrendChart title="Orders Over Time" data={data.sales_analytics?.orders_over_time || []} />
          </section>

          <section className="dashboard-split-grid">
            <FunnelChart title="Conversion Funnel" items={data.sales_analytics?.conversion_funnel || []} />
            <HorizontalBars title="Traffic Sources" items={data.traffic_sources || []} />
          </section>

          <section className="dashboard-bottom-grid">
            <article className="admin-panel-card">
              <header>
                <h3>Top Selling Products</h3>
              </header>
              <div className="top-products-grid">
                {(data.product_performance?.top_selling_products || []).map((product) => (
                  <div key={product.id} className="top-product-card">
                    <div className="top-product-image" style={{ backgroundImage: `url(${product.image || ''})` }} />
                    <div className="top-product-meta">
                      <strong>{product.name}</strong>
                      <p>{product.units_sold} units sold</p>
                      <div>
                        <span>{compactCurrency(product.revenue)}</span>
                        <small>{product.stock_status}</small>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </article>

            <article className="admin-panel-card">
              <header>
                <h3>Customer Analytics</h3>
              </header>
              <div className="customer-stats-row">
                <div><small>Active Users</small><strong>{data.customer_analytics?.active_users || 0}</strong></div>
                <div><small>Returning</small><strong>{data.customer_analytics?.returning_customers || 0}</strong></div>
                <div><small>New</small><strong>{data.customer_analytics?.new_customers || 0}</strong></div>
              </div>
              <MiniWorldMap countries={data.customer_analytics?.top_countries || []} />
            </article>

            <article className="admin-panel-card">
              <header>
                <h3>Real-Time Activity Feed</h3>
              </header>
              <div className="activity-list">
                {(data.realtime_activity || []).map((item) => (
                  <div key={item.id || item.timestamp} className="activity-row">
                    <span className={`activity-type type-${item.type}`}>{item.type?.replace('_', ' ')}</span>
                    <p>{item.message}</p>
                    <small>{new Date(item.timestamp).toLocaleString()}</small>
                  </div>
                ))}
              </div>
            </article>
          </section>
        </>
      ) : null}
    </div>
  );
}

export default Dashboard;
