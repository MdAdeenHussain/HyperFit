import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import api from '../services/api';
import ProductGallery from '../components/ProductGallery';
import ProductCard from '../components/ProductCard';
import SkeletonLoader from '../components/SkeletonLoader';
import { useCart } from '../context/CartContext';
import { setMeta, inr } from '../utils/helpers';
import Reveal from '../components/Reveal';

function ProductDetail() {
  const { slug } = useParams();
  const { addToCart } = useCart();

  const [product, setProduct] = useState(null);
  const [related, setRelated] = useState([]);
  const [reviews, setReviews] = useState([]);
  const [size, setSize] = useState('');
  const [color, setColor] = useState('');
  const [quantity, setQuantity] = useState(1);
  const [reviewForm, setReviewForm] = useState({ rating: 5, title: '', comment: '' });
  const [actionState, setActionState] = useState('idle');

  useEffect(() => {
    async function load() {
      const { data } = await api.get(`/products/${slug}`);
      setProduct(data.product);
      setRelated(data.related || []);
      setReviews(data.reviews || []);
      setSize(data.product.sizes?.[0] || '');
      setColor(data.product.colors?.[0] || '');

      setMeta({
        title: data.product.seo_title || `${data.product.name} | HyperFit`,
        description: data.product.seo_description || data.product.description?.slice(0, 160)
      });

      const viewed = JSON.parse(localStorage.getItem('hf_recently_viewed') || '[]');
      const next = [data.product, ...viewed.filter((item) => item.id !== data.product.id)].slice(0, 8);
      localStorage.setItem('hf_recently_viewed', JSON.stringify(next));
    }

    load();
  }, [slug]);

  const recentlyViewed = useMemo(() => {
    const list = JSON.parse(localStorage.getItem('hf_recently_viewed') || '[]');
    return list.filter((item) => item.slug !== slug).slice(0, 6);
  }, [slug]);

  const addReview = async () => {
    await api.post(`/products/${slug}/reviews`, reviewForm);
    const { data } = await api.get(`/products/${slug}`);
    setReviews(data.reviews || []);
    setReviewForm({ rating: 5, title: '', comment: '' });
  };

  const addWishlist = async () => {
    await api.post('/user/wishlist', { product_id: product.id });
    setActionState('wishlisted');
    window.setTimeout(() => setActionState('idle'), 1200);
  };

  const shareProduct = async () => {
    const url = window.location.href;
    if (navigator.share) {
      await navigator.share({ title: product.name, text: product.description, url });
      return;
    }
    await navigator.clipboard.writeText(url);
    setActionState('shared');
    window.setTimeout(() => setActionState('idle'), 1200);
  };

  const handleAddToCart = async () => {
    await addToCart({ product_id: product.id, quantity, size, color });
    setActionState('carted');
    window.setTimeout(() => setActionState('idle'), 1200);
  };

  if (!product) return <div className="hf-container page-gap"><SkeletonLoader rows={4} /></div>;

  return (
    <div className="hf-container page-gap product-page">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify({
        '@context': 'https://schema.org',
        '@type': 'Product',
        name: product.name,
        description: product.description,
        sku: product.sku,
        offers: {
          '@type': 'Offer',
          priceCurrency: 'INR',
          price: product.price,
          availability: product.stock > 0 ? 'https://schema.org/InStock' : 'https://schema.org/OutOfStock'
        }
      }) }} />

      <div className="detail-grid">
        <Reveal threshold={0.1}><ProductGallery images={product.images} /></Reveal>

        <Reveal as="section" className="product-detail-panel" delay={0.08} threshold={0.1}>
          <h1>{product.name}</h1>
          <p className="price">{inr(product.price)}</p>
          <p>{product.description}</p>

          <label>Size</label>
          <select value={size} onChange={(event) => setSize(event.target.value)}>{product.sizes.map((item) => <option key={item}>{item}</option>)}</select>

          <label>Color</label>
          <select value={color} onChange={(event) => setColor(event.target.value)}>{product.colors.map((item) => <option key={item}>{item}</option>)}</select>

          <label>Quantity</label>
          <input type="number" min="1" value={quantity} onChange={(event) => setQuantity(Number(event.target.value))} />

          <div className="row-actions">
            <button onClick={handleAddToCart}>Add to Cart</button>
            <button onClick={addWishlist}>Wishlist</button>
            <button onClick={shareProduct}>Share</button>
          </div>

          <small className="product-action-feedback">
            {actionState === 'carted' && 'Added to cart'}
            {actionState === 'wishlisted' && 'Added to wishlist'}
            {actionState === 'shared' && 'Link copied'}
          </small>

          <article className="card-block">
            <h4>Fabric Details</h4>
            <p>{product.fabric_details || 'Performance knit fabric with breathable support.'}</p>
            <h4>Size Guide</h4>
            <p>{product.size_guide || 'True to fit. For oversized look, choose one size up.'}</p>
          </article>
        </Reveal>
      </div>

      <Reveal as="section" threshold={0.15}>
        <h2>Related Products</h2>
        <div className="product-grid">{related.map((item) => <ProductCard key={item.id} product={item} />)}</div>
      </Reveal>

      <Reveal as="section" threshold={0.15}>
        <h2>Recently Viewed</h2>
        <div className="product-grid">{recentlyViewed.map((item) => <ProductCard key={item.id} product={item} />)}</div>
      </Reveal>

      <Reveal as="section" threshold={0.15}>
        <h2>Reviews</h2>
        <div className="review-grid">
          {reviews.map((review) => (
            <article className="review-card" key={review.id}>
              <h4>{review.title || 'Review'}</h4>
              <p>{review.comment}</p>
              <small>{review.rating}/5 by {review.user}</small>
            </article>
          ))}
        </div>

        <div className="review-form">
          <input placeholder="Title" value={reviewForm.title} onChange={(event) => setReviewForm((prev) => ({ ...prev, title: event.target.value }))} />
          <textarea placeholder="Write your review" value={reviewForm.comment} onChange={(event) => setReviewForm((prev) => ({ ...prev, comment: event.target.value }))} />
          <select value={reviewForm.rating} onChange={(event) => setReviewForm((prev) => ({ ...prev, rating: Number(event.target.value) }))}>
            {[5, 4, 3, 2, 1].map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <button onClick={addReview}>Submit Review</button>
        </div>
      </Reveal>

      <div className="mobile-sticky-cart">
        <div>
          <small>{inr(product.price)}</small>
          <strong>{product.name}</strong>
        </div>
        <button onClick={handleAddToCart}>Add to Cart</button>
      </div>
    </div>
  );
}

export default ProductDetail;
