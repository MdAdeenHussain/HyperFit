import { useEffect, useState } from 'react';
import api from '../services/api';
import ProductCard from '../components/ProductCard';

function Wishlist() {
  const [items, setItems] = useState([]);

  const load = async () => {
    const { data } = await api.get('/user/wishlist');
    setItems(data.items || []);
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="hf-container page-gap">
      <h1>Wishlist</h1>
      <div className="product-grid">
        {items.map((item) => (
          <div key={item.id}>
            <ProductCard product={{ ...item, images: [item.image], slug: item.slug }} />
            <button onClick={async () => {
              await api.delete(`/user/wishlist/${item.product_id}`);
              load();
            }}>Remove</button>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Wishlist;
