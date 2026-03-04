import { useEffect, useState } from 'react';
import api from '../services/api';
import ProductCard from '../components/ProductCard';
import CategoryToggle from '../components/CategoryToggle';
import SkeletonLoader from '../components/SkeletonLoader';
import { setMeta } from '../utils/helpers';

function Home() {
  const [recommended, setRecommended] = useState([]);
  const [featured, setFeatured] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setMeta({
      title: 'HyperFit | Minimal Activewear for Men and Women',
      description: 'Shop minimalist premium activewear with a Nike x H&M inspired aesthetic.'
    });

    async function load() {
      try {
        const [rec, feat] = await Promise.all([api.get('/products/recommended'), api.get('/products/featured')]);
        setRecommended(rec.data.items || []);
        setFeatured(feat.data.items || []);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div className="hf-container page-gap">
      <section className="hero-section">
        <div>
          <p className="eyebrow">HyperFit 2026 Collection</p>
          <h1>Minimal Performance Wear for Everyday Movement.</h1>
          <p>Precision cuts, breathable fabric and modern silhouettes designed for urban performance.</p>
          <a className="solid-link" href="/shop">Shop Now</a>
        </div>
      </section>

      <section>
        <h2>Recommended Products</h2>
        {loading ? (
          <SkeletonLoader rows={3} />
        ) : (
          <div className="product-grid">{recommended.slice(0, 6).map((item) => <ProductCard key={item.id} product={item} />)}</div>
        )}
      </section>

      <CategoryToggle />

      <section className="featured-highlight">
        <div>
          <h2>Featured Performance Drop</h2>
          <p>Engineered comfort, sleek style, made to move from workout to city streets.</p>
        </div>
      </section>

      <section>
        <h2>Latest Listing</h2>
        {loading ? <SkeletonLoader rows={3} /> : <div className="product-grid">{featured.map((item) => <ProductCard key={item.id} product={item} />)}</div>}
      </section>
    </div>
  );
}

export default Home;
