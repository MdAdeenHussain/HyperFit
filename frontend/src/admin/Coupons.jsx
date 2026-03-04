import { useEffect, useState } from 'react';
import api from '../services/api';

function Coupons() {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState({ code: '', discount_type: 'percent', discount_value: 10, expiry_date: '', max_usage: 100 });

  const load = async () => {
    const { data } = await api.get('/admin/coupons');
    setRows(data.items || []);
  };

  useEffect(() => { load(); }, []);

  const createCoupon = async () => {
    await api.post('/admin/coupons', form);
    setForm({ ...form, code: '' });
    load();
  };

  return (
    <div className="admin-page">
      <h2>Coupons</h2>
      <div className="form-grid">
        <input placeholder="Code" value={form.code} onChange={(e) => setForm((p) => ({ ...p, code: e.target.value }))} />
        <select value={form.discount_type} onChange={(e) => setForm((p) => ({ ...p, discount_type: e.target.value }))}>
          <option value="percent">Percentage</option>
          <option value="flat">Flat</option>
        </select>
        <input type="number" placeholder="Value" value={form.discount_value} onChange={(e) => setForm((p) => ({ ...p, discount_value: Number(e.target.value) }))} />
        <input type="datetime-local" value={form.expiry_date} onChange={(e) => setForm((p) => ({ ...p, expiry_date: e.target.value }))} />
        <input type="number" placeholder="Max usage" value={form.max_usage} onChange={(e) => setForm((p) => ({ ...p, max_usage: Number(e.target.value) }))} />
        <button onClick={createCoupon}>Create Coupon</button>
      </div>

      <ul>
        {rows.map((row) => <li key={row.id}>{row.code} · {row.discount_type} {row.discount_value} · {row.used_count}/{row.max_usage}</li>)}
      </ul>
    </div>
  );
}

export default Coupons;
