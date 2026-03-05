import { useEffect, useMemo, useState } from 'react';
import api from '../services/api';
import ProductCard from '../components/ProductCard';
import CategoryToggle from '../components/CategoryToggle';
import SkeletonLoader from '../components/SkeletonLoader';
import { setMeta } from '../utils/helpers';
import Reveal from '../components/Reveal';
import HeroSection from '../components/HeroSection';
import FeaturedProduct from '../components/FeaturedProduct';
import ReviewCard from '../components/ReviewCard';
import NewsletterForm from '../components/NewsletterForm';

const CUSTOMER_REVIEWS = [
  {
    name: 'Aman Verma',
    meta: 'CrossFit athlete',
    quote: 'The fit is sharp and the fabric stays light even through high-intensity sessions.'
  },
  {
    name: 'Neha Shah',
    meta: 'Runner',
    quote: 'Looks premium and performs even better. Finally activewear I can train and travel in.'
  },
  {
    name: 'Riya Patel',
    meta: 'Strength coach',
    quote: 'HyperFit keeps movement unrestricted, and the build quality feels top-tier.'
  }
];

function Home() {
  const [recommended, setRecommended] = useState([]);
  const [featured, setFeatured] = useState([]);
  const [allProducts, setAllProducts] = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setMeta({
      title: 'HyperFit | Premium Performance Wear',
      description: 'Engineered activewear with premium motion-first design for men and women.'
    });

    async function load() {
      try {
        const [rec, feat, products, categoryRows] = await Promise.all([
          api.get('/products/recommended'),
          api.get('/products/featured'),
          api.get('/products', { params: { per_page: 24, sort: 'new' } }),
          api.get('/products/categories')
        ]);
        setRecommended(rec.data.items || []);
        setFeatured(feat.data.items || []);
        setAllProducts(products.data.items || []);
        setCategories(categoryRows.data.items || []);
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  const groupedProducts = useMemo(() => {
    if (!allProducts.length) return { men: [], women: [] };

    const categoryGender = categories.reduce((map, category) => {
      map[category.id] = category.gender;
      return map;
    }, {});

    const men = [];
    const women = [];

    allProducts.forEach((product) => {
      const gender = categoryGender[product.category_id];
      if (gender === 'women') women.push(product);
      else men.push(product);
    });

    if (!women.length) {
      const midpoint = Math.ceil(allProducts.length / 2);
      return {
        men: allProducts.slice(0, midpoint),
        women: allProducts.slice(midpoint)
      };
    }

    return { men, women };
  }, [allProducts, categories]);

  const heroImage = featured[0]?.images?.[0] || recommended[0]?.images?.[0];
  const highlightProduct = featured[0] || recommended[0];

  return (
    <div className="hf-container page-gap home-page">
      <HeroSection heroImage={heroImage} />

      <Reveal as="section" className="featured-strip" threshold={0.15}>
        <div className="section-head">
          <h2>Featured Product Strip</h2>
          <p>Curated high-performance essentials.</p>
        </div>

        {loading ? (
          <SkeletonLoader rows={4} variant="cards" />
        ) : (
          <div className="featured-strip-scroll">
            {featured.slice(0, 6).map((item) => (
              <div key={item.id} className="strip-item">
                <ProductCard product={item} />
              </div>
            ))}
          </div>
        )}
      </Reveal>

      <CategoryToggle />

      <FeaturedProduct product={highlightProduct} />

      <Reveal as="section" className="product-listing-section" threshold={0.15}>
        <div className="section-head">
          <h2>Men</h2>
          <p>Performance pieces built for hard training days.</p>
        </div>
        {loading ? <SkeletonLoader rows={6} variant="cards" /> : <div className="product-grid">{groupedProducts.men.map((item) => <ProductCard key={item.id} product={item} />)}</div>}
      </Reveal>

      <Reveal as="section" className="product-listing-section" threshold={0.15}>
        <div className="section-head">
          <h2>Women</h2>
          <p>Precision-fit movement wear with elevated comfort.</p>
        </div>
        {loading ? <SkeletonLoader rows={6} variant="cards" /> : <div className="product-grid">{groupedProducts.women.map((item) => <ProductCard key={item.id} product={item} />)}</div>}
      </Reveal>

      <Reveal as="section" className="brand-story" threshold={0.15}>
        <p className="eyebrow">Brand Story</p>
        <h2>HyperFit is designed for athletes who demand performance, comfort, and style.</h2>
        <p>
          We build apparel that moves with intent. Every seam, panel, and fabric decision is focused on lightweight control,
          long-session comfort, and understated visual confidence.
        </p>
      </Reveal>

      <Reveal as="section" className="reviews-section" threshold={0.15}>
        <div className="section-head">
          <h2>Reviews</h2>
          <p>What athletes say after training in HyperFit.</p>
        </div>
        <div className="review-grid">
          {CUSTOMER_REVIEWS.map((review) => (
            <ReviewCard key={review.name} review={review} />
          ))}
        </div>
      </Reveal>

      <Reveal as="section" className="newsletter-section" threshold={0.15}>
        <h2>Newsletter</h2>
        <p>Get first access to new drops and limited runs.</p>
        <NewsletterForm />
      </Reveal>
    </div>
  );
}

export default Home;
