import { useEffect, useState } from 'react';
import api from '../services/api';

function Customers() {
  const [rows, setRows] = useState([]);

  const load = async () => {
    const { data } = await api.get('/admin/customers');
    setRows(data.items || []);
  };

  useEffect(() => { load(); }, []);

  const exportCsv = async () => {
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000/api'}/admin/export/customers.csv`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('hf_access_token')}` }
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'customers.csv';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="admin-page">
      <h2>Customer Management</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.name}</td>
                <td>{row.email}</td>
                <td>{row.phone}</td>
                <td>{row.is_active ? 'Active' : 'Blocked'}</td>
                <td>
                  {!row.is_admin && (
                    <button onClick={async () => {
                      await api.patch(`/admin/customers/${row.id}/block`, { block: row.is_active });
                      load();
                    }}>{row.is_active ? 'Block' : 'Unblock'}</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button onClick={exportCsv}>Export CSV</button>
    </div>
  );
}

export default Customers;
