import { useEffect, useState } from 'react';
import api from '../services/api';
import ProductCard from '../components/ProductCard';
import Reveal from '../components/Reveal';

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
    <div className="hf-container page-gap wishlist-page">
      <Reveal threshold={0.1}><h1>Wishlist</h1></Reveal>
      <div className="product-grid">
        {items.map((item, index) => (
          <Reveal key={item.id} delay={index * 0.04} threshold={0.08}>
            <div className="wishlist-item-wrap">
              <ProductCard product={{ ...item, images: [item.image], slug: item.slug }} />
              <button onClick={async () => {
                await api.delete(`/user/wishlist/${item.product_id}`);
                load();
              }}>Remove</button>
            </div>
          </Reveal>
        ))}
      </div>
    </div>
  );
}

export default Wishlist;
