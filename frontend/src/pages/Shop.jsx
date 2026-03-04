import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../services/api';
import ProductCard from '../components/ProductCard';
import SkeletonLoader from '../components/SkeletonLoader';
import { SORT_OPTIONS } from '../utils/constants';
import { setMeta } from '../utils/helpers';

const FILTER_DEFAULTS = {
  search: '',
  min_price: '',
  max_price: '',
  size: '',
  color: '',
  category: '',
  rating: '',
  sort: 'new'
};

function Shop() {
  const [query] = useSearchParams();
  const [filters, setFilters] = useState(FILTER_DEFAULTS);
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setMeta({ title: 'Shop HyperFit Products', description: 'Filter by price, size, color, category and rating.' });
  }, []);

  useEffect(() => {
    setFilters((prev) => ({ ...prev, category: query.get('category') || '', sort: query.get('sort') || prev.sort }));
  }, [query]);

  const params = useMemo(() => {
    const payload = {};
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== '' && v !== null && v !== undefined) payload[k] = v;
    });
    return payload;
  }, [filters]);

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/products', { params });
      setProducts(data.items || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [params.category, params.sort]);

  return (
    <div className="hf-container page-gap">
      <h1>Shop</h1>

      <div className="shop-filters">
        <input placeholder="Search products" value={filters.search} onChange={(e) => setFilters((p) => ({ ...p, search: e.target.value }))} />
        <input placeholder="Min price" type="number" value={filters.min_price} onChange={(e) => setFilters((p) => ({ ...p, min_price: e.target.value }))} />
        <input placeholder="Max price" type="number" value={filters.max_price} onChange={(e) => setFilters((p) => ({ ...p, max_price: e.target.value }))} />
        <input placeholder="Size" value={filters.size} onChange={(e) => setFilters((p) => ({ ...p, size: e.target.value }))} />
        <input placeholder="Colour" value={filters.color} onChange={(e) => setFilters((p) => ({ ...p, color: e.target.value }))} />
        <input placeholder="Category slug" value={filters.category} onChange={(e) => setFilters((p) => ({ ...p, category: e.target.value }))} />
        <input placeholder="Rating" type="number" min="1" max="5" value={filters.rating} onChange={(e) => setFilters((p) => ({ ...p, rating: e.target.value }))} />
        <select value={filters.sort} onChange={(e) => setFilters((p) => ({ ...p, sort: e.target.value }))}>
          {SORT_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
        <button onClick={load}>Apply</button>
      </div>

      {loading ? <SkeletonLoader rows={5} /> : <div className="product-grid">{products.map((item) => <ProductCard key={item.id} product={item} />)}</div>}
    </div>
  );
}

export default Shop;
