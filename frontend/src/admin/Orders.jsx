import { useEffect, useState } from 'react';
import api from '../services/api';

function Orders() {
  const [rows, setRows] = useState([]);

  const load = async () => {
    const { data } = await api.get('/admin/orders');
    setRows(data.items || []);
  };

  useEffect(() => { load(); }, []);

  const updateStatus = async (orderNumber, status) => {
    await api.patch(`/admin/orders/${orderNumber}`, { status });
    load();
  };

  return (
    <div className="admin-page">
      <h2>Order Management</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Order #</th><th>Customer</th><th>Status</th><th>Total</th><th>Update</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.order_number}>
                <td>{row.order_number}</td>
                <td>{row.customer}</td>
                <td>{row.status}</td>
                <td>{row.total}</td>
                <td>
                  <select defaultValue={row.status} onChange={(e) => updateStatus(row.order_number, e.target.value)}>
                    {['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'].map((s) => <option key={s}>{s}</option>)}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default Orders;
