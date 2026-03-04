import { useEffect, useState } from 'react';
import api from '../services/api';

const EMPTY = {
  name: '', description: '', price: '', stock: '', sku: '', category_id: '',
  images: '', sizes: 'S,M,L', colors: 'Black,White'
};

function Products() {
  const [rows, setRows] = useState([]);
  const [categories, setCategories] = useState([]);
  const [form, setForm] = useState(EMPTY);

  const load = async () => {
    const [p, c] = await Promise.all([api.get('/admin/products'), api.get('/admin/categories')]);
    setRows(p.data.items || []);
    setCategories(c.data.items || []);
  };

  useEffect(() => { load(); }, []);

  const createProduct = async () => {
    await api.post('/admin/products', {
      ...form,
      price: Number(form.price),
      stock: Number(form.stock),
      category_id: Number(form.category_id),
      images: form.images.split(',').map((x) => x.trim()).filter(Boolean),
      sizes: form.sizes.split(',').map((x) => x.trim()),
      colors: form.colors.split(',').map((x) => x.trim())
    });
    setForm(EMPTY);
    load();
  };

  return (
    <div className="admin-page">
      <h2>Product Management</h2>
      <div className="form-grid">
        <input placeholder="Name" value={form.name} onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))} />
        <textarea placeholder="Description" value={form.description} onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))} />
        <input placeholder="Price" type="number" value={form.price} onChange={(e) => setForm((p) => ({ ...p, price: e.target.value }))} />
        <input placeholder="Stock" type="number" value={form.stock} onChange={(e) => setForm((p) => ({ ...p, stock: e.target.value }))} />
        <input placeholder="SKU" value={form.sku} onChange={(e) => setForm((p) => ({ ...p, sku: e.target.value }))} />
        <select value={form.category_id} onChange={(e) => setForm((p) => ({ ...p, category_id: e.target.value }))}>
          <option value="">Select category</option>
          {categories.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <input placeholder="Image URLs comma separated" value={form.images} onChange={(e) => setForm((p) => ({ ...p, images: e.target.value }))} />
        <input placeholder="Sizes comma separated" value={form.sizes} onChange={(e) => setForm((p) => ({ ...p, sizes: e.target.value }))} />
        <input placeholder="Colors comma separated" value={form.colors} onChange={(e) => setForm((p) => ({ ...p, colors: e.target.value }))} />
        <button onClick={createProduct}>Add Product</button>
      </div>

      <div className="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Price</th><th>Stock</th><th>Actions</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.name}</td>
                <td>{row.price}</td>
                <td>{row.stock}</td>
                <td><button onClick={async () => { await api.delete(`/admin/products/${row.id}`); load(); }}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default Products;
