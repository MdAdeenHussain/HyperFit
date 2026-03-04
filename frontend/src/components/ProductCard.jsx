import { Link } from 'react-router-dom';
import { inr } from '../utils/helpers';

function ProductCard({ product }) {
  return (
    <article className="product-card">
      <Link to={`/product/${product.slug}`}>
        <img loading="lazy" src={product.images?.[0] || '/placeholder.png'} alt={product.name} />
      </Link>
      <div className="product-content">
        <h3>{product.name}</h3>
        <p>{inr(product.price)}</p>
      </div>
    </article>
  );
}

export default ProductCard;
