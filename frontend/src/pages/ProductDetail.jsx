import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import api from '../services/api';
import ProductGallery from '../components/ProductGallery';
import ProductCard from '../components/ProductCard';
import SkeletonLoader from '../components/SkeletonLoader';
import { useCart } from '../context/CartContext';
import { setMeta, inr } from '../utils/helpers';

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
    alert('Added to wishlist');
  };

  const shareProduct = async () => {
    const url = window.location.href;
    if (navigator.share) {
      await navigator.share({ title: product.name, text: product.description, url });
      return;
    }
    await navigator.clipboard.writeText(url);
    alert('Link copied');
  };

  if (!product) return <div className="hf-container page-gap"><SkeletonLoader rows={4} /></div>;

  return (
    <div className="hf-container page-gap">
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
        <ProductGallery images={product.images} />

        <section>
          <h1>{product.name}</h1>
          <p className="price">{inr(product.price)}</p>
          <p>{product.description}</p>

          <label>Size</label>
          <select value={size} onChange={(e) => setSize(e.target.value)}>{product.sizes.map((s) => <option key={s}>{s}</option>)}</select>

          <label>Colour</label>
          <select value={color} onChange={(e) => setColor(e.target.value)}>{product.colors.map((c) => <option key={c}>{c}</option>)}</select>

          <label>Quantity</label>
          <input type="number" min="1" value={quantity} onChange={(e) => setQuantity(Number(e.target.value))} />

          <div className="row-actions">
            <button onClick={() => addToCart({ product_id: product.id, quantity, size, color })}>Add to Cart</button>
            <button onClick={addWishlist}>Wishlist</button>
            <button onClick={shareProduct}>Share</button>
          </div>

          <article className="card-block">
            <h4>Fabric Details</h4>
            <p>{product.fabric_details || 'Performance knit fabric with breathable support.'}</p>
            <h4>Size Guide</h4>
            <p>{product.size_guide || 'True to fit. For oversized look, choose one size up.'}</p>
          </article>
        </section>
      </div>

      <section>
        <h2>Related Products</h2>
        <div className="product-grid">{related.map((item) => <ProductCard key={item.id} product={item} />)}</div>
      </section>

      <section>
        <h2>Recently Viewed</h2>
        <div className="product-grid">{recentlyViewed.map((item) => <ProductCard key={item.id} product={item} />)}</div>
      </section>

      <section>
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
          <input placeholder="Title" value={reviewForm.title} onChange={(e) => setReviewForm((p) => ({ ...p, title: e.target.value }))} />
          <textarea placeholder="Write your review" value={reviewForm.comment} onChange={(e) => setReviewForm((p) => ({ ...p, comment: e.target.value }))} />
          <select value={reviewForm.rating} onChange={(e) => setReviewForm((p) => ({ ...p, rating: Number(e.target.value) }))}>
            {[5, 4, 3, 2, 1].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
          <button onClick={addReview}>Submit Review</button>
        </div>
      </section>
    </div>
  );
}

export default ProductDetail;
