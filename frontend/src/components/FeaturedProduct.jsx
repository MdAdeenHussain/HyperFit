import { Link } from 'react-router-dom';
import Reveal from './Reveal';

function FeaturedProduct({ product }) {
  return (
    <Reveal as="section" className="featured-spotlight" threshold={0.15}>
      <div className="spotlight-image-wrap">
        <img loading="lazy" src={product?.images?.[0] || '/placeholder.png'} alt={product?.name || 'HyperFit Compression Series'} />
      </div>

      <div className="spotlight-copy">
        <p className="eyebrow">Feature Product Highlight</p>
        <h2>{product?.name || 'HyperFit Compression Series'}</h2>
        <p>
          {product?.description || 'Lightweight compression support, sweat-control weave, and mobility-first cuts for everyday training.'}
        </p>
        <ul>
          <li>Compression-knit performance fabric</li>
          <li>Adaptive 4-way stretch</li>
          <li>Moisture-wick finish and anti-odor comfort</li>
        </ul>
        <Link className="solid-link" to={product ? `/product/${product.slug}` : '/shop'}>Shop Now</Link>
      </div>
    </Reveal>
  );
}

export default FeaturedProduct;
