import { useEffect, useState } from 'react';
import api from '../services/api';
import { inr } from '../utils/helpers';

function Dashboard() {
  const [data, setData] = useState(null);

  useEffect(() => {
    api.get('/admin/dashboard').then((res) => setData(res.data));
  }, []);

  if (!data) return <div>Loading dashboard...</div>;

  return (
    <div className="admin-page">
      <h2>Dashboard Analytics</h2>
      <div className="stats-grid">
        <div className="stat"><span>Revenue</span><strong>{inr(data.metrics.revenue)}</strong></div>
        <div className="stat"><span>Orders</span><strong>{data.metrics.orders}</strong></div>
        <div className="stat"><span>Customers</span><strong>{data.metrics.customers}</strong></div>
        <div className="stat"><span>Products</span><strong>{data.metrics.products}</strong></div>
      </div>

      <h3>Sales Graph</h3>
      <div className="simple-graph">
        {data.sales_graph.map((point) => (
          <div key={point.date} className="bar-wrap" title={`${point.date}: ${point.orders} orders`}>
            <div className="bar" style={{ height: `${Math.max(10, point.orders * 8)}px` }} />
            <small>{point.date.slice(5)}</small>
          </div>
        ))}
      </div>

      <h3>Top Selling Products</h3>
      <ul>
        {data.top_selling_products.map((item) => <li key={item.name}>{item.name} - {item.units} units</li>)}
      </ul>
    </div>
  );
}

export default Dashboard;
