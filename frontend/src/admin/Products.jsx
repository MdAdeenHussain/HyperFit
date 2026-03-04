import { useEffect, useMemo, useState } from 'react';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

const EMPTY_PRODUCT = {
  name: '',
  description: '',
  category_id: '',
  price: '',
  discount: '',
  stock: '',
  sizes: 'S,M,L,XL',
  colors: 'Black,Blue',
  sku: '',
  image_url: ''
};

const EMPTY_CATEGORY = {
  name: '',
  parent_id: '',
  gender: 'men',
  image_url: ''
};

function Products() {
  const [products, setProducts] = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [form, setForm] = useState(EMPTY_PRODUCT);
  const [editId, setEditId] = useState(null);
  const [imageList, setImageList] = useState([]);

  const [categoryForm, setCategoryForm] = useState(EMPTY_CATEGORY);
  const [categoryEditId, setCategoryEditId] = useState(null);

  const topCategories = useMemo(() => categories.filter((cat) => !cat.parent_id), [categories]);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [productRes, categoryRes] = await Promise.all([adminService.getProducts(), adminService.getCategories()]);
      setProducts(productRes.data.items || []);
      setCategories(categoryRes.data.items || []);
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load products');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const resetForm = () => {
    setEditId(null);
    setForm(EMPTY_PRODUCT);
    setImageList([]);
  };

  const submitProduct = async (event) => {
    event.preventDefault();

    const payload = {
      name: form.name,
      description: form.description,
      category_id: Number(form.category_id),
      price: Number(form.price),
      discount: Number(form.discount || 0),
      stock: Number(form.stock),
      sku: form.sku,
      images: imageList,
      sizes: form.sizes.split(',').map((item) => item.trim()).filter(Boolean),
      colors: form.colors.split(',').map((item) => item.trim()).filter(Boolean)
    };

    if (editId) {
      await adminService.updateProduct(editId, payload);
    } else {
      await adminService.createProduct(payload);
    }

    resetForm();
    load();
  };

  const submitCategory = async (event) => {
    event.preventDefault();
    const payload = {
      ...categoryForm,
      parent_id: categoryForm.parent_id ? Number(categoryForm.parent_id) : null
    };

    if (categoryEditId) {
      await adminService.updateCategory(categoryEditId, payload);
    } else {
      await adminService.createCategory(payload);
    }

    setCategoryEditId(null);
    setCategoryForm(EMPTY_CATEGORY);
    load();
  };

  const pushImage = () => {
    if (!form.image_url.trim()) return;
    setImageList((prev) => [...prev, form.image_url.trim()]);
    setForm((prev) => ({ ...prev, image_url: '' }));
  };

  const onDragStart = (index) => (event) => {
    event.dataTransfer.setData('text/plain', String(index));
  };

  const onDrop = (toIndex) => (event) => {
    event.preventDefault();
    const fromIndex = Number(event.dataTransfer.getData('text/plain'));
    if (Number.isNaN(fromIndex) || fromIndex === toIndex) return;

    setImageList((prev) => {
      const next = [...prev];
      const [moved] = next.splice(fromIndex, 1);
      next.splice(toIndex, 0, moved);
      return next;
    });
  };

  const handleImageUpload = async (event) => {
    const files = Array.from(event.target.files || []);
    if (!files.length) return;

    const encoded = await Promise.all(
      files.map(
        (file) =>
          new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsDataURL(file);
          })
      )
    );
    setImageList((prev) => [...prev, ...encoded.filter(Boolean)]);
    event.target.value = '';
  };

  const startEditProduct = (item) => {
    setEditId(item.id);
    setForm({
      name: item.name,
      description: item.description,
      category_id: item.category_id,
      price: item.price,
      discount: item.discount || 0,
      stock: item.stock,
      sizes: (item.sizes || []).join(','),
      colors: (item.colors || []).join(','),
      sku: item.sku,
      image_url: ''
    });
    setImageList(item.images || []);
  };

  if (loading) return <AdminSkeleton rows={10} />;

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>Product Management</h1>
          <p>Manage full product CRUD, category hierarchy, pricing and sortable images.</p>
        </div>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}

      <section className="admin-dual-grid">
        <article className="admin-panel-card">
          <header><h3>{editId ? 'Edit Product' : 'Create Product'}</h3></header>
          <form className="admin-form-grid" onSubmit={submitProduct}>
            <input placeholder="Product Name" value={form.name} onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))} required />
            <textarea placeholder="Description" value={form.description} onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))} required />
            <select value={form.category_id} onChange={(e) => setForm((prev) => ({ ...prev, category_id: e.target.value }))} required>
              <option value="">Select category</option>
              {categories.map((cat) => <option key={cat.id} value={cat.id}>{cat.name}</option>)}
            </select>
            <div className="form-cols-2">
              <input type="number" min="0" placeholder="Price" value={form.price} onChange={(e) => setForm((prev) => ({ ...prev, price: e.target.value }))} required />
              <input type="number" min="0" max="90" placeholder="Discount %" value={form.discount} onChange={(e) => setForm((prev) => ({ ...prev, discount: e.target.value }))} />
            </div>
            <div className="form-cols-2">
              <input type="number" min="0" placeholder="Stock" value={form.stock} onChange={(e) => setForm((prev) => ({ ...prev, stock: e.target.value }))} required />
              <input placeholder="SKU" value={form.sku} onChange={(e) => setForm((prev) => ({ ...prev, sku: e.target.value }))} required />
            </div>
            <input placeholder="Sizes (comma separated)" value={form.sizes} onChange={(e) => setForm((prev) => ({ ...prev, sizes: e.target.value }))} />
            <input placeholder="Colors (comma separated)" value={form.colors} onChange={(e) => setForm((prev) => ({ ...prev, colors: e.target.value }))} />

            <div className="inline-action-row">
              <input placeholder="Image URL" value={form.image_url} onChange={(e) => setForm((prev) => ({ ...prev, image_url: e.target.value }))} />
              <button type="button" className="ghost" onClick={pushImage}>Add image</button>
            </div>
            <input type="file" accept="image/*" multiple onChange={handleImageUpload} />

            <div className="image-sort-grid">
              {imageList.map((image, index) => (
                <div
                  key={`${image}-${index}`}
                  className="sortable-image"
                  draggable
                  onDragStart={onDragStart(index)}
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={onDrop(index)}
                >
                  <div style={{ backgroundImage: `url(${image})` }} />
                  <small>Drag to reorder</small>
                </div>
              ))}
            </div>

            <div className="form-btn-row">
              <button type="submit" className="admin-btn">{editId ? 'Update Product' : 'Create Product'}</button>
              {editId ? <button type="button" className="ghost" onClick={resetForm}>Cancel</button> : null}
            </div>
          </form>
        </article>

        <article className="admin-panel-card">
          <header><h3>{categoryEditId ? 'Edit Category' : 'Category Management'}</h3></header>
          <form className="admin-form-grid" onSubmit={submitCategory}>
            <input placeholder="Category Name" value={categoryForm.name} onChange={(e) => setCategoryForm((prev) => ({ ...prev, name: e.target.value }))} required />
            <select value={categoryForm.gender} onChange={(e) => setCategoryForm((prev) => ({ ...prev, gender: e.target.value }))}>
              <option value="men">Men</option>
              <option value="women">Women</option>
            </select>
            <select value={categoryForm.parent_id} onChange={(e) => setCategoryForm((prev) => ({ ...prev, parent_id: e.target.value }))}>
              <option value="">No Parent (Root Category)</option>
              {topCategories.map((cat) => <option key={cat.id} value={cat.id}>{cat.name}</option>)}
            </select>
            <input placeholder="Category image URL" value={categoryForm.image_url} onChange={(e) => setCategoryForm((prev) => ({ ...prev, image_url: e.target.value }))} />
            <div className="form-btn-row">
              <button type="submit" className="admin-btn">{categoryEditId ? 'Update Category' : 'Add Category'}</button>
              {categoryEditId ? <button type="button" className="ghost" onClick={() => { setCategoryEditId(null); setCategoryForm(EMPTY_CATEGORY); }}>Cancel</button> : null}
            </div>
          </form>

          <div className="admin-table-scroll">
            <table className="admin-table compact">
              <thead>
                <tr><th>Name</th><th>Parent</th><th>Gender</th><th>Actions</th></tr>
              </thead>
              <tbody>
                {categories.map((cat) => (
                  <tr key={cat.id}>
                    <td>{cat.name}</td>
                    <td>{categories.find((item) => item.id === cat.parent_id)?.name || '-'}</td>
                    <td>{cat.gender}</td>
                    <td>
                      <div className="row-actions-inline">
                        <button
                          className="ghost"
                          onClick={() => {
                            setCategoryEditId(cat.id);
                            setCategoryForm({
                              name: cat.name,
                              parent_id: cat.parent_id || '',
                              gender: cat.gender,
                              image_url: cat.image_url || ''
                            });
                          }}
                        >Edit</button>
                        <button className="ghost danger" onClick={() => adminService.deleteCategory(cat.id).then(load)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>
      </section>

      <section className="admin-table-card">
        <header className="table-header-row">
          <strong>Product Catalog</strong>
          <span>{products.length} items</span>
        </header>
        <div className="admin-table-scroll">
          <table className="admin-table">
            <thead>
              <tr>
                <th>Product</th>
                <th>Category</th>
                <th>Price</th>
                <th>Discount</th>
                <th>Stock</th>
                <th>SKU</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {products.map((item) => (
                <tr key={item.id}>
                  <td>{item.name}</td>
                  <td>{item.category || '-'}</td>
                  <td>{new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format(item.price || 0)}</td>
                  <td>{item.discount || 0}%</td>
                  <td>{item.stock}</td>
                  <td>{item.sku}</td>
                  <td>
                    <div className="row-actions-inline">
                      <button className="ghost" onClick={() => startEditProduct(item)}>Edit</button>
                      <button className="ghost danger" onClick={() => adminService.deleteProduct(item.id).then(load)}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default Products;
