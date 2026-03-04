import { useEffect, useState } from 'react';
import api from '../services/api';

function Inventory() {
  const [rows, setRows] = useState([]);

  useEffect(() => {
    api.get('/admin/inventory').then((res) => setRows(res.data.items || []));
  }, []);

  return (
    <div className="admin-page">
      <h2>Inventory</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Stock</th><th>Sizes</th><th>Status</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.name}</td>
                <td>{row.stock}</td>
                <td>{(row.sizes || []).join(', ')}</td>
                <td>{row.is_out_of_stock ? 'Out of stock' : row.is_low_stock ? 'Low stock' : 'Healthy'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default Inventory;
