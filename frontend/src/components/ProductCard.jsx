import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { inr } from '../utils/helpers';
import { useCart } from '../context/CartContext';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';

function HeartIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 20.55 4.9 13.8a4.86 4.86 0 0 1 6.87-6.88L12 7.14l.23-.22a4.86 4.86 0 1 1 6.87 6.88L12 20.55Zm-5.97-7.84L12 18.38l5.97-5.67a3.36 3.36 0 0 0-4.75-4.75L12 9.18l-1.22-1.22a3.36 3.36 0 0 0-4.75 4.75Z" fill="currentColor" />
    </svg>
  );
}

function BagIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M8.25 7.5V7a3.75 3.75 0 1 1 7.5 0v.5h1.5A1.75 1.75 0 0 1 19 9.25v9A2.75 2.75 0 0 1 16.25 21h-8.5A2.75 2.75 0 0 1 5 18.25v-9A1.75 1.75 0 0 1 6.75 7.5h1.5Zm1.5 0h4.5V7a2.25 2.25 0 1 0-4.5 0v.5Zm-3 1.5a.25.25 0 0 0-.25.25v9c0 .69.56 1.25 1.25 1.25h8.5c.69 0 1.25-.56 1.25-1.25v-9a.25.25 0 0 0-.25-.25h-1.5v1.25a.75.75 0 0 1-1.5 0V9h-4.5v1.25a.75.75 0 0 1-1.5 0V9h-1.5Z" fill="currentColor" />
    </svg>
  );
}

function StarIcon({ active }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className={active ? 'active' : ''}>
      <path d="m12 3.9 2.48 5.02 5.54.8-4.01 3.9.95 5.52L12 16.53 7.04 19.14l.95-5.52-4.01-3.9 5.54-.8L12 3.9Z" fill="currentColor" />
    </svg>
  );
}

function getComparePrice(product) {
  const comparePrice = Number(product.compare_price || product.derivedComparePrice || 0);
  const price = Number(product.price || 0);
  return comparePrice > price ? comparePrice : null;
}

function getDiscountPercent(product) {
  if (product.derivedDiscountPercent) return Number(product.derivedDiscountPercent);

  const comparePrice = getComparePrice(product);
  const price = Number(product.price || 0);
  if (!comparePrice || comparePrice <= price) return 0;
  return Math.round(((comparePrice - price) / comparePrice) * 100);
}

function getBrand(product) {
  if (product.derivedBrand) return product.derivedBrand;
  return 'HyperFit';
}

function getBadges(product, discountPercent) {
  const badges = [];

  if (product.is_on_sale || discountPercent > 0) {
    badges.push({ label: 'Sale', tone: 'sale' });
  }

  if (product.is_new_arrival) {
    badges.push({ label: 'New', tone: 'new' });
  }

  if (product.is_featured || product.is_recommended || ((product.review_count || 0) >= 3 && (product.rating_avg || 0) >= 4)) {
    badges.push({ label: 'Trending', tone: 'trending' });
  }

  return badges.slice(0, 2);
}

function ProductCard({ product }) {
  const navigate = useNavigate();
  const image = product.images?.[0] || product.image || '/placeholder.png';
  const productId = product.id || product.product_id;
  const productHref = product.slug ? `/product/${product.slug}` : '/shop';
  const comparePrice = getComparePrice(product);
  const discountPercent = getDiscountPercent(product);
  const displayBrand = getBrand(product);
  const badges = getBadges(product, discountPercent);

  const { addToCart } = useCart();
  const { isAuthenticated } = useAuth();

  const [adding, setAdding] = useState(false);
  const [added, setAdded] = useState(false);
  const [wishlistPulse, setWishlistPulse] = useState(false);

  const rating = Number(product.rating_avg || 0);
  const reviewCount = Number(product.review_count || 0);
  const roundedRating = Math.round(rating);
  const categoryLabel = product.category_parent ? `${product.category_parent} / ${product.category}` : product.category || 'Training apparel';

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

    if (!productId) return;
    if (!isAuthenticated) {
      navigate('/login');
      return;
    }

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
      <div className="product-media-shell">
        <Link to={productHref} className="product-media-link">
          <div className="product-card-badges">
            {badges.map((badge) => (
              <span key={badge.label} className={`product-badge ${badge.tone}`}>{badge.label}</span>
            ))}
          </div>

          <img loading="lazy" src={image} alt={product.name} />
          <div className="product-media-fade" />
        </Link>

        <button
          type="button"
          className={`product-wishlist-btn ${wishlistPulse ? 'pulse' : ''}`}
          onClick={onWishlist}
          aria-label={`Save ${product.name} to wishlist`}
        >
          <HeartIcon />
        </button>

        <div className="product-quick-actions">
          <button type="button" onClick={onQuickAdd} disabled={adding} aria-label={`Quick add ${product.name} to cart`}>
            <BagIcon />
            <span>{adding ? 'Adding' : added ? 'Added' : 'Quick Add'}</span>
          </button>
        </div>
      </div>

      <div className="product-content">
        <Link to={productHref} className="product-copy-link">
          <p className="product-brand">{displayBrand}</p>
          <h3>{product.name}</h3>
          <p className="product-subline">{categoryLabel}</p>
        </Link>

        <div className="product-price-row">
          <strong className="product-price-current">{inr(product.price)}</strong>
          {comparePrice ? <span className="product-price-compare">{inr(comparePrice)}</span> : null}
          {discountPercent ? <span className="product-discount-pill">{discountPercent}% OFF</span> : null}
        </div>

        <div className="product-rating-row">
          <div className="product-stars" aria-label={reviewCount ? `${rating.toFixed(1)} out of 5 stars` : 'Not rated yet'}>
            {Array.from({ length: 5 }).map((_, index) => (
              <StarIcon key={index} active={index < roundedRating} />
            ))}
          </div>
          <span className="product-rating-copy">
            {reviewCount ? `${rating.toFixed(1)} (${reviewCount})` : 'Fresh drop'}
          </span>
        </div>
      </div>
    </article>
  );
}

export default ProductCard;
