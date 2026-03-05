import { useState } from 'react';
import { Link } from 'react-router-dom';
import { inr } from '../utils/helpers';
import { useCart } from '../context/CartContext';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

function ProductCard({ product }) {
  const image = product.images?.[0] || product.image || '/placeholder.png';
  const productId = product.id || product.product_id;
  const { addToCart } = useCart();
  const { isAuthenticated } = useAuth();

  const [adding, setAdding] = useState(false);
  const [added, setAdded] = useState(false);
  const [wishlistPulse, setWishlistPulse] = useState(false);

  const onQuickAdd = async (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (adding || !productId) return;

    setAdding(true);
    try {
      await addToCart({
        product_id: productId,
        quantity: 1,
        size: product.sizes?.[0] || null,
        color: product.colors?.[0] || null,
        price: product.price,
        product: {
          id: productId,
          name: product.name,
          price: product.price,
          image
        }
      });
      setAdded(true);
      window.setTimeout(() => setAdded(false), 1200);
    } finally {
      setAdding(false);
    }
  };

  const onWishlist = async (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (!isAuthenticated || !productId) return;

    try {
      await api.post('/user/wishlist', { product_id: productId });
      setWishlistPulse(true);
      window.setTimeout(() => setWishlistPulse(false), 700);
    } catch (_error) {
      // Keep wishlist interactions non-blocking for card hover flow.
    }
  };

  return (
    <article className="product-card reveal-card">
      <Link to={`/product/${product.slug}`} className="product-media-link">
        <img loading="lazy" src={image} alt={product.name} />
        <div className="product-actions-float">
          <button onClick={onQuickAdd} disabled={adding}>{adding ? 'Adding...' : added ? 'Added' : 'Quick Add'}</button>
          <button className={wishlistPulse ? 'pulse' : ''} onClick={onWishlist} aria-label="Save to wishlist">Wishlist</button>
        </div>
      </Link>

      <div className="product-content">
        <h3>{product.name}</h3>
        <p>{inr(product.price)}</p>
      </div>
    </article>
  );
}

export default ProductCard;
