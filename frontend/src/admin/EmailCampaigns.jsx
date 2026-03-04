import { useEffect, useState } from 'react';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

const EMPTY_FORM = {
  title: '',
  subject: '',
  campaign_type: 'newsletter',
  content: ''
};

function EmailCampaigns() {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await adminService.getCampaigns();
      setRows(data.items || []);
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load campaigns');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const sendCampaign = async (event) => {
    event.preventDefault();
    setSending(true);
    setError('');
    try {
      await adminService.sendCampaign(form);
      setForm(EMPTY_FORM);
      load();
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to send campaign');
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>Email Campaigns</h1>
          <p>Send newsletters, product launches and discount campaigns with delivery metrics.</p>
        </div>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}

      <section className="admin-panel-card">
        <header><h3>Create Campaign</h3></header>
        <form className="admin-form-grid" onSubmit={sendCampaign}>
          <input placeholder="Campaign title" value={form.title} onChange={(e) => setForm((prev) => ({ ...prev, title: e.target.value }))} required />
          <input placeholder="Email subject" value={form.subject} onChange={(e) => setForm((prev) => ({ ...prev, subject: e.target.value }))} required />
          <select value={form.campaign_type} onChange={(e) => setForm((prev) => ({ ...prev, campaign_type: e.target.value }))}>
            <option value="newsletter">Newsletter</option>
            <option value="promotion">Promotional</option>
            <option value="launch">Product Launch</option>
            <option value="discount">Discount Campaign</option>
          </select>
          <textarea placeholder="Campaign content" value={form.content} onChange={(e) => setForm((prev) => ({ ...prev, content: e.target.value }))} required />
          <div className="form-btn-row">
            <button className="admin-btn" type="submit" disabled={sending}>{sending ? 'Sending...' : 'Send Campaign'}</button>
          </div>
        </form>
      </section>

      {loading ? <AdminSkeleton rows={6} /> : (
        <section className="admin-table-card">
          <header><h3>Campaign Performance</h3></header>
          <div className="admin-table-scroll">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Campaign</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Recipients</th>
                  <th>Open Rate</th>
                  <th>Click Rate</th>
                  <th>Conversion Rate</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td>{row.title}</td>
                    <td>{row.campaign_type}</td>
                    <td><span className="pill success">{row.status}</span></td>
                    <td>{row.sent_count}</td>
                    <td>{row.open_rate}%</td>
                    <td>{row.click_rate}%</td>
                    <td>{row.conversion_rate}%</td>
                    <td>{new Date(row.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

export default EmailCampaigns;
