import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import { inr } from '../utils/helpers';

function Account() {
  const { user, refreshProfile } = useAuth();
  const [form, setForm] = useState({ first_name: '', last_name: '', phone: '' });
  const [orders, setOrders] = useState([]);
  const [addresses, setAddresses] = useState([]);
  const [address, setAddress] = useState({ name: '', line1: '', line2: '', city: '', state: '', country: 'India', pincode: '', phone: '' });

  useEffect(() => {
    if (!user) return;
    setForm({ first_name: user.first_name || '', last_name: user.last_name || '', phone: user.phone || '' });

    async function load() {
      const [myOrders, myAddresses] = await Promise.all([api.get('/user/orders'), api.get('/user/addresses')]);
      setOrders(myOrders.data.items || []);
      setAddresses(myAddresses.data.items || []);
    }
    load();
  }, [user]);

  const updateProfile = async () => {
    await api.put('/user/account', form);
    await refreshProfile();
    alert('Profile updated');
  };

  const downloadInvoice = async (orderNumber) => {
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000/api'}/orders/${orderNumber}/invoice`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('hf_access_token')}` }
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `invoice_${orderNumber}.pdf`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const addAddress = async () => {
    await api.post('/user/addresses', address);
    const { data } = await api.get('/user/addresses');
    setAddresses(data.items || []);
  };

  if (!user) return <div className="hf-container page-gap">Login required.</div>;

  return (
    <div className="hf-container page-gap">
      <h1>My Account</h1>

      <section className="card-block">
        <h3>Profile</h3>
        <div className="form-grid">
          <input value={form.first_name} onChange={(e) => setForm((p) => ({ ...p, first_name: e.target.value }))} />
          <input value={form.last_name} onChange={(e) => setForm((p) => ({ ...p, last_name: e.target.value }))} />
          <input value={user.email} disabled />
          <input value={form.phone} onChange={(e) => setForm((p) => ({ ...p, phone: e.target.value }))} />
          <button onClick={updateProfile}>Save</button>
        </div>
      </section>

      <section className="card-block">
        <h3>Address Management</h3>
        <div className="form-grid">
          {Object.keys(address).map((key) => (
            <input key={key} placeholder={key} value={address[key]} onChange={(e) => setAddress((p) => ({ ...p, [key]: e.target.value }))} />
          ))}
          <button onClick={addAddress}>Add Address</button>
        </div>
        <div className="address-list">
          {addresses.map((item) => (
            <article key={item.id} className="mini-card">
              <h4>{item.name}</h4>
              <p>{item.line1}, {item.city}, {item.state}</p>
              <p>{item.pincode}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="card-block">
        <h3>Order History & Tracking</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Order #</th>
                <th>Status</th>
                <th>Ordered Date</th>
                <th>Expected Delivery</th>
                <th>Price</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {orders.map((item) => (
                <tr key={item.order_number}>
                  <td>{item.order_number}</td>
                  <td>{item.status}</td>
                  <td>{new Date(item.ordered_date).toLocaleDateString()}</td>
                  <td>{item.expected_delivery ? new Date(item.expected_delivery).toLocaleDateString() : '-'}</td>
                  <td>{inr(item.price)}</td>
                  <td>
                    <button onClick={() => downloadInvoice(item.order_number)}>Invoice</button>
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

export default Account;
