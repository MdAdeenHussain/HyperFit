import { useEffect, useState } from 'react';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

function Integrations() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError('');
      try {
        const { data } = await adminService.getIntegrations();
        setRows(data.items || []);
      } catch (err) {
        setError(err?.response?.data?.error || err?.message || 'Unable to load integrations');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>Integrations</h1>
          <p>External service connectivity for payments, shipping and email automation.</p>
        </div>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}
      {loading ? <AdminSkeleton rows={4} /> : null}

      {!loading ? (
        <section className="integration-grid">
          {rows.map((row) => (
            <article key={row.name} className="admin-panel-card">
              <h3>{row.name}</h3>
              <p>{row.status === 'connected' ? 'Connected and ready for production workflows.' : 'Not configured. Add credentials in environment variables.'}</p>
              <span className={row.status === 'connected' ? 'pill success' : 'pill warning'}>{row.status}</span>
            </article>
          ))}
        </section>
      ) : null}
    </div>
  );
}

export default Integrations;
