import { useEffect, useState } from 'react';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

const EMPTY = {
  free_shipping_amount: 1999,
  tax_rate: 0.12,
  currency: 'INR',
  email_templates: {
    order_confirmation_subject: '',
    newsletter_subject: ''
  },
  seo_defaults: {
    title: '',
    description: ''
  }
};

function Settings() {
  const [form, setForm] = useState(EMPTY);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError('');
      try {
        const { data } = await adminService.getSiteSettings();
        setForm({ ...EMPTY, ...(data.value || {}) });
      } catch (err) {
        setError(err?.response?.data?.error || err?.message || 'Unable to load settings');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError('');
    setMessage('');
    try {
      await adminService.updateSiteSettings(form);
      setMessage('Site-wide settings updated successfully.');
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to save settings');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <AdminSkeleton rows={8} />;

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>Settings</h1>
          <p>Manage shipping thresholds, taxes, currencies, email templates and SEO defaults.</p>
        </div>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}
      {message ? <div className="admin-success">{message}</div> : null}

      <section className="admin-panel-card">
        <form className="admin-form-grid" onSubmit={submit}>
          <h3>Commerce Defaults</h3>
          <div className="form-cols-3">
            <label>
              Free Shipping Amount
              <input type="number" value={form.free_shipping_amount} onChange={(e) => setForm((prev) => ({ ...prev, free_shipping_amount: Number(e.target.value) }))} />
            </label>
            <label>
              Tax Rate
              <input type="number" step="0.01" value={form.tax_rate} onChange={(e) => setForm((prev) => ({ ...prev, tax_rate: Number(e.target.value) }))} />
            </label>
            <label>
              Currency
              <input value={form.currency} onChange={(e) => setForm((prev) => ({ ...prev, currency: e.target.value }))} />
            </label>
          </div>

          <h3>Email Templates</h3>
          <input
            placeholder="Order confirmation subject"
            value={form.email_templates?.order_confirmation_subject || ''}
            onChange={(e) => setForm((prev) => ({
              ...prev,
              email_templates: {
                ...(prev.email_templates || {}),
                order_confirmation_subject: e.target.value
              }
            }))}
          />
          <input
            placeholder="Newsletter subject"
            value={form.email_templates?.newsletter_subject || ''}
            onChange={(e) => setForm((prev) => ({
              ...prev,
              email_templates: {
                ...(prev.email_templates || {}),
                newsletter_subject: e.target.value
              }
            }))}
          />

          <h3>SEO Defaults</h3>
          <input
            placeholder="Default SEO title"
            value={form.seo_defaults?.title || ''}
            onChange={(e) => setForm((prev) => ({
              ...prev,
              seo_defaults: {
                ...(prev.seo_defaults || {}),
                title: e.target.value
              }
            }))}
          />
          <textarea
            placeholder="Default SEO description"
            value={form.seo_defaults?.description || ''}
            onChange={(e) => setForm((prev) => ({
              ...prev,
              seo_defaults: {
                ...(prev.seo_defaults || {}),
                description: e.target.value
              }
            }))}
          />

          <div className="form-btn-row">
            <button className="admin-btn" type="submit" disabled={saving}>{saving ? 'Saving...' : 'Save Settings'}</button>
          </div>
        </form>
      </section>
    </div>
  );
}

export default Settings;
