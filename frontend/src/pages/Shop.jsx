import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../services/api';
import ProductCard from '../components/ProductCard';
import SkeletonLoader from '../components/SkeletonLoader';
import { SORT_OPTIONS } from '../utils/constants';
import { setMeta } from '../utils/helpers';
import Reveal from '../components/Reveal';

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
  const [filterOpen, setFilterOpen] = useState(true);
  const [mobileFilterOpen, setMobileFilterOpen] = useState(false);

  useEffect(() => {
    setMeta({ title: 'Shop HyperFit Products', description: 'Filter by price, size, color, category and rating.' });
  }, []);

  useEffect(() => {
    setFilters((prev) => ({ ...prev, category: query.get('category') || '', sort: query.get('sort') || prev.sort }));
  }, [query]);

  const params = useMemo(() => {
    const payload = {};
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== '' && value !== null && value !== undefined) payload[key] = value;
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
      setMobileFilterOpen(false);
    }
  };

  useEffect(() => {
    load();
  }, [params.category, params.sort]);

  const filterFields = (
    <div className="shop-filters">
      <input placeholder="Search products" value={filters.search} onChange={(event) => setFilters((prev) => ({ ...prev, search: event.target.value }))} />
      <input placeholder="Min price" type="number" value={filters.min_price} onChange={(event) => setFilters((prev) => ({ ...prev, min_price: event.target.value }))} />
      <input placeholder="Max price" type="number" value={filters.max_price} onChange={(event) => setFilters((prev) => ({ ...prev, max_price: event.target.value }))} />
      <input placeholder="Size" value={filters.size} onChange={(event) => setFilters((prev) => ({ ...prev, size: event.target.value }))} />
      <input placeholder="Color" value={filters.color} onChange={(event) => setFilters((prev) => ({ ...prev, color: event.target.value }))} />
      <input placeholder="Category slug" value={filters.category} onChange={(event) => setFilters((prev) => ({ ...prev, category: event.target.value }))} />
      <input placeholder="Rating" type="number" min="1" max="5" value={filters.rating} onChange={(event) => setFilters((prev) => ({ ...prev, rating: event.target.value }))} />
      <select value={filters.sort} onChange={(event) => setFilters((prev) => ({ ...prev, sort: event.target.value }))}>
        {SORT_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
      <button onClick={load}>Apply Filters</button>
    </div>
  );

  return (
    <div className="hf-container page-gap shop-page">
      <Reveal className="shop-header" threshold={0.1}>
        <div>
          <h1>Shop</h1>
          <p>Performance-first apparel with premium finishes.</p>
        </div>
        <div className="shop-header-actions">
          <button className="text-link" onClick={() => setFilterOpen((value) => !value)}>{filterOpen ? 'Hide' : 'Show'} Filters</button>
          <div className="sort-pill">
            <small>Sort</small>
            <select value={filters.sort} onChange={(event) => setFilters((prev) => ({ ...prev, sort: event.target.value }))}>
              {SORT_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>
        </div>
      </Reveal>

      <div className={`shop-filters-wrap ${filterOpen ? 'open' : ''}`}>
        {filterFields}
      </div>

      <button className="shop-mobile-filter-btn" onClick={() => setMobileFilterOpen(true)}>Filters</button>

      <div className={`shop-mobile-sheet ${mobileFilterOpen ? 'open' : ''}`}>
        <button className="sheet-backdrop" onClick={() => setMobileFilterOpen(false)} aria-label="Close filter panel" />
        <div className="sheet-content">
          <div className="sheet-head">
            <h3>Filters</h3>
            <button onClick={() => setMobileFilterOpen(false)}>Close</button>
          </div>
          {filterFields}
        </div>
      </div>

      {loading ? (
        <SkeletonLoader rows={8} variant="cards" />
      ) : (
        <div className="product-grid">
          {products.map((item, index) => (
            <Reveal key={item.id} delay={index * 0.03} threshold={0.08}>
              <ProductCard product={item} />
            </Reveal>
          ))}
        </div>
      )}
    </div>
  );
}

export default Shop;
