import { useEffect, useState } from 'react';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

const EMPTY_COUPON = {
  code: '',
  discount_type: 'percent',
  discount_value: 10,
  expiry_date: '',
  max_usage: 100,
  min_order_amount: 0,
  product_id: '',
  category_id: ''
};

function Coupons() {
  const [rows, setRows] = useState([]);
  const [categories, setCategories] = useState([]);
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [form, setForm] = useState(EMPTY_COUPON);
  const [editId, setEditId] = useState(null);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [couponsRes, categoriesRes, productsRes] = await Promise.all([
        adminService.getCoupons(),
        adminService.getCategories(),
        adminService.getProducts()
      ]);
      setRows(couponsRes.data.items || []);
      setCategories(categoriesRes.data.items || []);
      setProducts(productsRes.data.items || []);
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load coupons');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const submit = async (event) => {
    event.preventDefault();
    const payload = {
      ...form,
      discount_value: Number(form.discount_value),
      max_usage: Number(form.max_usage),
      min_order_amount: Number(form.min_order_amount),
      product_id: form.product_id ? Number(form.product_id) : null,
      category_id: form.category_id ? Number(form.category_id) : null
    };

    if (editId) {
      await adminService.updateCoupon(editId, payload);
    } else {
      await adminService.createCoupon(payload);
    }

    setForm(EMPTY_COUPON);
    setEditId(null);
    load();
  };

  const startEdit = (item) => {
    setEditId(item.id);
    setForm({
      code: item.code,
      discount_type: item.discount_type,
      discount_value: item.discount_value,
      expiry_date: item.expiry_date ? item.expiry_date.slice(0, 16) : '',
      max_usage: item.max_usage,
      min_order_amount: item.min_order_amount || 0,
      product_id: item.product_id || '',
      category_id: item.category_id || ''
    });
  };

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>Discounts & Coupons</h1>
          <p>Create percentage or flat discounts with expiry, usage limits and targeting rules.</p>
        </div>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}

      <section className="admin-panel-card">
        <header><h3>{editId ? 'Update Coupon' : 'Create Coupon'}</h3></header>
        <form className="admin-form-grid" onSubmit={submit}>
          <input placeholder="Coupon code" value={form.code} onChange={(e) => setForm((prev) => ({ ...prev, code: e.target.value.toUpperCase() }))} required />
          <div className="form-cols-2">
            <select value={form.discount_type} onChange={(e) => setForm((prev) => ({ ...prev, discount_type: e.target.value }))}>
              <option value="percent">Percentage discount</option>
              <option value="flat">Flat discount</option>
            </select>
            <input type="number" min="0" value={form.discount_value} onChange={(e) => setForm((prev) => ({ ...prev, discount_value: e.target.value }))} />
          </div>
          <div className="form-cols-2">
            <input type="datetime-local" value={form.expiry_date} onChange={(e) => setForm((prev) => ({ ...prev, expiry_date: e.target.value }))} required />
            <input type="number" min="1" value={form.max_usage} onChange={(e) => setForm((prev) => ({ ...prev, max_usage: e.target.value }))} placeholder="Usage limit" />
          </div>
          <input type="number" min="0" value={form.min_order_amount} onChange={(e) => setForm((prev) => ({ ...prev, min_order_amount: e.target.value }))} placeholder="Minimum cart value" />

          <div className="form-cols-2">
            <select value={form.product_id} onChange={(e) => setForm((prev) => ({ ...prev, product_id: e.target.value }))}>
              <option value="">All products</option>
              {products.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
            <select value={form.category_id} onChange={(e) => setForm((prev) => ({ ...prev, category_id: e.target.value }))}>
              <option value="">All categories</option>
              {categories.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
          </div>

          <div className="form-btn-row">
            <button className="admin-btn" type="submit">{editId ? 'Update Coupon' : 'Create Coupon'}</button>
            {editId ? <button type="button" className="ghost" onClick={() => { setEditId(null); setForm(EMPTY_COUPON); }}>Cancel</button> : null}
          </div>
        </form>
      </section>

      {loading ? <AdminSkeleton rows={6} /> : (
        <section className="admin-table-card">
          <div className="admin-table-scroll">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Code</th>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Usage</th>
                  <th>Expiry</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td>{row.code}</td>
                    <td>{row.discount_type}</td>
                    <td>{row.discount_value}</td>
                    <td>{row.used_count}/{row.max_usage}</td>
                    <td>{row.expiry_date ? new Date(row.expiry_date).toLocaleString() : '-'}</td>
                    <td><span className={row.is_active ? 'pill success' : 'pill danger'}>{row.is_active ? 'Active' : 'Disabled'}</span></td>
                    <td>
                      <div className="row-actions-inline">
                        <button className="ghost" onClick={() => startEdit(row)}>Edit</button>
                        <button className="ghost danger" onClick={() => adminService.deleteCoupon(row.id).then(load)}>Delete</button>
                      </div>
                    </td>
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

export default Coupons;
