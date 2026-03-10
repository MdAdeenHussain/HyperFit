import { useDeferredValue, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import api from '../services/api';
import ProductCard from '../components/ProductCard';
import SkeletonLoader from '../components/SkeletonLoader';
import { SORT_OPTIONS } from '../utils/constants';
import { inr, setMeta } from '../utils/helpers';
import Reveal from '../components/Reveal';

const FILTER_DEFAULTS = {
  search: '',
  category: '',
  categories: [],
  brands: [],
  sizes: [],
  colors: [],
  materials: [],
  fit: '',
  sale: '',
  new_arrival: '',
  sort: 'featured',
  min_price: '',
  max_price: ''
};

const CATEGORY_PRIORITY = ['T-Shirts', 'Shirts', 'Hoodies', 'Jackets', 'Pants', 'Compression', 'Shorts', 'Leggings', 'Sports Bra'];
const SIZE_ORDER = ['XS', 'S', 'M', 'L', 'XL', 'XXL', '3XL'];
const MATERIAL_KEYWORDS = ['Cotton', 'Polyester', 'Nylon', 'Elastane', 'Spandex', 'Mesh', 'Fleece', 'French Terry', 'Rib', 'Lycra'];
const FIT_FALLBACK = ['Compression', 'Regular', 'Relaxed', 'Slim'];

const COLOR_SWATCHES = {
  black: '#101419',
  white: '#f5f5f5',
  blue: '#2958d3',
  navy: '#182743',
  red: '#d9363e',
  green: '#2f8f5b',
  olive: '#708238',
  grey: '#7c8794',
  gray: '#7c8794',
  charcoal: '#454c56',
  beige: '#d7cab0',
  cream: '#ece3d3',
  brown: '#8f613d',
  yellow: '#e1b94a',
  orange: '#f07f3c',
  purple: '#7757c8',
  pink: '#df7eaf',
  maroon: '#7a1f2b',
  teal: '#16838c'
};

function parseList(value) {
  return (value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalize(value) {
  return String(value || '').trim().toLowerCase();
}

function toFiniteNumber(value) {
  const next = Number(value);
  return Number.isFinite(next) ? next : null;
}

function formatLabel(value) {
  return String(value || '')
    .replace(/^(brand|label|line|collection|fit|material):/i, '')
    .replace(/[-_]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function hashColor(value) {
  const seed = Array.from(normalize(value)).reduce((sum, char) => sum + char.charCodeAt(0), 0);
  return `hsl(${seed % 360} 58% 52%)`;
}

function resolveColorSwatch(color) {
  return COLOR_SWATCHES[normalize(color)] || hashColor(color);
}

function inferBrand(product) {
  const tags = (product.tags || []).map((item) => String(item));
  const brandTag = tags.find((item) => /^(brand|label|line|collection):/i.test(item));
  if (brandTag) return formatLabel(brandTag);

  const skuPrefix = (product.sku || '').split('-')[0];
  if (skuPrefix && skuPrefix.length > 2 && normalize(skuPrefix) !== 'hf') {
    return formatLabel(skuPrefix);
  }

  return 'HyperFit';
}

function inferMaterials(product) {
  const source = [product.fabric_details, product.description, ...(product.tags || [])].join(' ').toLowerCase();
  return MATERIAL_KEYWORDS.filter((item) => source.includes(item.toLowerCase()));
}

function inferFit(product) {
  const source = [product.name, product.description, product.category, product.category_parent, ...(product.tags || [])]
    .join(' ')
    .toLowerCase();

  if (source.includes('compression')) return 'Compression';
  if (source.includes('relaxed') || source.includes('oversized')) return 'Relaxed';
  if (source.includes('slim') || source.includes('tapered')) return 'Slim';
  return 'Regular';
}

function getComparePrice(product) {
  const comparePrice = Number(product.compare_price || 0);
  const price = Number(product.price || 0);
  return comparePrice > price ? comparePrice : null;
}

function getDiscountPercent(product) {
  const comparePrice = getComparePrice(product);
  const price = Number(product.price || 0);
  if (!comparePrice || comparePrice <= price) return 0;
  return Math.round(((comparePrice - price) / comparePrice) * 100);
}

function compareProducts(left, right, sort) {
  const leftPrice = Number(left.price || 0);
  const rightPrice = Number(right.price || 0);
  const leftDate = Date.parse(left.created_at || 0) || 0;
  const rightDate = Date.parse(right.created_at || 0) || 0;

  if (sort === 'price_asc') return leftPrice - rightPrice;
  if (sort === 'price_desc') return rightPrice - leftPrice;
  if (sort === 'best_selling') {
    return (right.review_count || 0) - (left.review_count || 0) || (right.rating_avg || 0) - (left.rating_avg || 0);
  }
  if (sort === 'new') return rightDate - leftDate;

  return (
    Number(Boolean(right.is_featured)) - Number(Boolean(left.is_featured)) ||
    Number(Boolean(right.is_recommended)) - Number(Boolean(left.is_recommended)) ||
    getDiscountPercent(right) - getDiscountPercent(left) ||
    (right.rating_avg || 0) - (left.rating_avg || 0) ||
    (right.review_count || 0) - (left.review_count || 0) ||
    rightDate - leftDate
  );
}

function sortCategoryOptions(options) {
  return [...options].sort((left, right) => {
    const leftIndex = CATEGORY_PRIORITY.indexOf(left.name);
    const rightIndex = CATEGORY_PRIORITY.indexOf(right.name);
    const leftRank = leftIndex === -1 ? CATEGORY_PRIORITY.length : leftIndex;
    const rightRank = rightIndex === -1 ? CATEGORY_PRIORITY.length : rightIndex;
    return leftRank - rightRank || left.name.localeCompare(right.name);
  });
}

function uniqueValues(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function FilterSection({ title, action, children }) {
  return (
    <section className="shop-filter-section">
      <div className="shop-filter-section-head">
        <h3>{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

function ToolbarIcon({ type }) {
  if (type === 'sort') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M8 6h10M8 12h7M8 18h4M4 6h.01M4 12h.01M4 18h.01" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      </svg>
    );
  }

  if (type === 'fit') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M7 4h10l2 5-3 2v8H8v-8L5 9l2-5Z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 7h16M7 12h10M9 17h6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

function Shop() {
  const [query] = useSearchParams();
  const [filters, setFilters] = useState(FILTER_DEFAULTS);
  const [searchInput, setSearchInput] = useState('');
  const deferredSearch = useDeferredValue(searchInput);

  const [products, setProducts] = useState([]);
  const [categories, setCategories] = useState([]);
  const [catalogMeta, setCatalogMeta] = useState({ total: 0 });
  const [categoriesLoading, setCategoriesLoading] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [requestKey, setRequestKey] = useState(0);

  const [desktopFiltersOpen, setDesktopFiltersOpen] = useState(true);
  const [mobileFilterOpen, setMobileFilterOpen] = useState(false);
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const [fitMenuOpen, setFitMenuOpen] = useState(false);

  useEffect(() => {
    const nextFilters = {
      ...FILTER_DEFAULTS,
      search: query.get('search') || '',
      category: query.get('category') || '',
      categories: parseList(query.get('categories')),
      brands: parseList(query.get('brands')),
      sizes: parseList(query.get('sizes')),
      colors: parseList(query.get('colors')),
      materials: parseList(query.get('materials')),
      fit: query.get('fit') || '',
      sale: query.get('sale') || '',
      new_arrival: query.get('new_arrival') || '',
      sort: query.get('sort') || FILTER_DEFAULTS.sort,
      min_price: query.get('min_price') || '',
      max_price: query.get('max_price') || ''
    };

    setFilters(nextFilters);
    setSearchInput(nextFilters.search);
    setMobileFilterOpen(false);
    setSortMenuOpen(false);
    setFitMenuOpen(false);
  }, [query]);

  useEffect(() => {
    const nextSearch = deferredSearch.trim();
    if (nextSearch === filters.search) return;
    setFilters((prev) => ({ ...prev, search: nextSearch }));
  }, [deferredSearch, filters.search]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        setSortMenuOpen(false);
        setFitMenuOpen(false);
        setMobileFilterOpen(false);
      }
    };

    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    let active = true;

    async function loadCategories() {
      setCategoriesLoading(true);
      try {
        const { data } = await api.get('/products/categories');
        if (!active) return;
        setCategories(data.items || []);
      } catch (_error) {
        if (!active) return;
        setCategories([]);
      } finally {
        if (active) setCategoriesLoading(false);
      }
    }

    loadCategories();
    return () => {
      active = false;
    };
  }, []);

  const categoriesById = useMemo(() => new Map(categories.map((item) => [item.id, item])), [categories]);
  const categoriesBySlug = useMemo(() => new Map(categories.map((item) => [item.slug, item])), [categories]);

  const activeCategory = categoriesBySlug.get(filters.category) || null;
  const activeRootCategory = useMemo(() => {
    if (!activeCategory) return null;
    if (!activeCategory.parent_id) return activeCategory;
    return categoriesById.get(activeCategory.parent_id) || null;
  }, [activeCategory, categoriesById]);

  const serverCategory = useMemo(() => {
    if (!filters.category) return '';
    if (filters.category === 'compression') return 'compression';
    if (!activeCategory) return filters.category;
    if (activeCategory.parent_id) return activeRootCategory?.slug || filters.category;
    return activeCategory.slug;
  }, [activeCategory, activeRootCategory, filters.category]);

  useEffect(() => {
    if (categoriesLoading) return undefined;

    let active = true;

    async function loadProducts() {
      setLoading(true);
      setError('');
      try {
        const { data } = await api.get('/products', {
          params: {
            per_page: 60,
            search: filters.search || undefined,
            category: serverCategory || undefined,
            sale: filters.sale || undefined,
            new_arrival: filters.new_arrival || undefined
          }
        });

        if (!active) return;
        setProducts(data.items || []);
        setCatalogMeta(data.meta || { total: (data.items || []).length });
      } catch (err) {
        if (!active) return;
        setProducts([]);
        setCatalogMeta({ total: 0 });
        setError(err?.response?.data?.error || err?.message || 'Unable to load products');
      } finally {
        if (active) setLoading(false);
      }
    }

    loadProducts();
    return () => {
      active = false;
    };
  }, [categoriesLoading, filters.search, filters.sale, filters.new_arrival, serverCategory, requestKey]);

  const catalogProducts = useMemo(() => (
    products.map((product) => ({
      ...product,
      derivedBrand: inferBrand(product),
      derivedMaterials: inferMaterials(product),
      derivedFit: inferFit(product),
      derivedComparePrice: getComparePrice(product),
      derivedDiscountPercent: getDiscountPercent(product)
    }))
  ), [products]);

  const priceBounds = useMemo(() => {
    const prices = catalogProducts.map((item) => Number(item.price || 0)).filter((value) => value > 0);
    if (!prices.length) return { min: 0, max: 5000 };

    const min = Math.floor(Math.min(...prices) / 100) * 100;
    const max = Math.ceil(Math.max(...prices) / 100) * 100;
    return { min, max: Math.max(min + 100, max) };
  }, [catalogProducts]);

  const priceStep = useMemo(() => {
    const spread = Math.max(100, priceBounds.max - priceBounds.min);
    if (spread > 5000) return 500;
    if (spread > 2000) return 250;
    return 100;
  }, [priceBounds]);

  const minFilterValue = toFiniteNumber(filters.min_price);
  const maxFilterValue = toFiniteNumber(filters.max_price);
  const selectedPriceMin = minFilterValue !== null ? Math.min(minFilterValue, priceBounds.max) : priceBounds.min;
  const selectedPriceMaxRaw = maxFilterValue !== null ? Math.max(maxFilterValue, priceBounds.min) : priceBounds.max;
  const selectedPriceMax = Math.max(selectedPriceMin, selectedPriceMaxRaw);

  const effectiveCategorySlugs = filters.categories.length
    ? filters.categories
    : activeCategory?.parent_id
      ? [activeCategory.slug]
      : [];

  const categoryOptions = useMemo(() => {
    const leafCategories = categories.filter((item) => item.parent_id);
    if (activeRootCategory) {
      return sortCategoryOptions(leafCategories.filter((item) => item.parent_id === activeRootCategory.id));
    }
    return sortCategoryOptions(leafCategories);
  }, [activeRootCategory, categories]);

  const categoryCounts = useMemo(() => (
    catalogProducts.reduce((accumulator, product) => {
      if (product.category_slug) {
        accumulator[product.category_slug] = (accumulator[product.category_slug] || 0) + 1;
      }
      return accumulator;
    }, {})
  ), [catalogProducts]);

  const brandOptions = useMemo(() => {
    const values = uniqueValues(catalogProducts.map((item) => item.derivedBrand)).sort((left, right) => left.localeCompare(right));
    return values.length ? values : ['HyperFit'];
  }, [catalogProducts]);

  const sizeOptions = useMemo(() => {
    const values = uniqueValues(catalogProducts.flatMap((item) => item.sizes || []));
    return values.sort((left, right) => {
      const leftIndex = SIZE_ORDER.indexOf(left);
      const rightIndex = SIZE_ORDER.indexOf(right);
      const leftRank = leftIndex === -1 ? SIZE_ORDER.length : leftIndex;
      const rightRank = rightIndex === -1 ? SIZE_ORDER.length : rightIndex;
      return leftRank - rightRank || left.localeCompare(right);
    });
  }, [catalogProducts]);

  const colorOptions = useMemo(() => (
    uniqueValues(catalogProducts.flatMap((item) => item.colors || [])).sort((left, right) => left.localeCompare(right))
  ), [catalogProducts]);

  const materialOptions = useMemo(() => (
    uniqueValues(catalogProducts.flatMap((item) => item.derivedMaterials || [])).sort((left, right) => left.localeCompare(right))
  ), [catalogProducts]);

  const fitOptions = useMemo(() => {
    const values = uniqueValues(catalogProducts.map((item) => item.derivedFit));
    const fallback = values.length ? values : FIT_FALLBACK;
    return [...fallback].sort((left, right) => FIT_FALLBACK.indexOf(left) - FIT_FALLBACK.indexOf(right));
  }, [catalogProducts]);

  const visibleProducts = useMemo(() => {
    const normalizedBrands = filters.brands.map(normalize);
    const normalizedSizes = filters.sizes.map(normalize);
    const normalizedColors = filters.colors.map(normalize);
    const normalizedMaterials = filters.materials.map(normalize);
    const normalizedFit = normalize(filters.fit);

    return catalogProducts
      .filter((product) => {
        const productSizes = (product.sizes || []).map(normalize);
        const productColors = (product.colors || []).map(normalize);
        const productMaterials = (product.derivedMaterials || []).map(normalize);
        const productBrand = normalize(product.derivedBrand);
        const productFit = normalize(product.derivedFit);
        const productPrice = Number(product.price || 0);

        if (effectiveCategorySlugs.length && !effectiveCategorySlugs.includes(product.category_slug)) return false;
        if (normalizedBrands.length && !normalizedBrands.includes(productBrand)) return false;
        if (normalizedSizes.length && !normalizedSizes.some((size) => productSizes.includes(size))) return false;
        if (normalizedColors.length && !normalizedColors.some((color) => productColors.includes(color))) return false;
        if (normalizedMaterials.length && !normalizedMaterials.some((material) => productMaterials.includes(material))) return false;
        if (normalizedFit && normalizedFit !== productFit) return false;
        if (productPrice < selectedPriceMin || productPrice > selectedPriceMax) return false;
        return true;
      })
      .sort((left, right) => compareProducts(left, right, filters.sort));
  }, [
    catalogProducts,
    effectiveCategorySlugs,
    filters.brands,
    filters.colors,
    filters.fit,
    filters.materials,
    filters.sizes,
    filters.sort,
    selectedPriceMax,
    selectedPriceMin
  ]);

  const pageContext = useMemo(() => {
    const defaultContext = {
      title: 'Shop',
      description: 'Explore performance-first HyperFit essentials with clean cuts, premium fabrics, and all-day comfort.',
      breadcrumbs: [
        { label: 'Home', to: '/' },
        { label: 'Collections', to: '/shop' },
        { label: 'Shop' }
      ]
    };

    if (activeCategory) {
      if (activeCategory.parent_id && activeRootCategory) {
        return {
          title: activeCategory.name,
          description: filters.search
            ? `Refined ${activeCategory.name.toLowerCase()} results for "${filters.search}" within the ${activeRootCategory.name.toLowerCase()} collection.`
            : `${activeCategory.name} built for training days, travel days, and everything between.`,
          breadcrumbs: [
            { label: 'Home', to: '/' },
            { label: 'Collections', to: '/shop' },
            { label: activeRootCategory.name, to: `/shop?category=${activeRootCategory.slug}&sort=featured` },
            { label: activeCategory.name }
          ]
        };
      }

      return {
        title: activeCategory.name,
        description: filters.search
          ? `Showing ${activeCategory.name.toLowerCase()} results for "${filters.search}".`
          : `${activeCategory.name} essentials arranged for movement, layering, and daily wear.`,
        breadcrumbs: [
          { label: 'Home', to: '/' },
          { label: 'Collections', to: '/shop' },
          { label: activeCategory.name }
        ]
      };
    }

    if (filters.sale === 'true') {
      return {
        title: 'Sale',
        description: filters.search
          ? `Discounted styles matching "${filters.search}".`
          : 'Marked-down performance staples with the same HyperFit finish and fit.',
        breadcrumbs: [
          { label: 'Home', to: '/' },
          { label: 'Collections', to: '/shop' },
          { label: 'Sale' }
        ]
      };
    }

    if (filters.new_arrival === 'true') {
      return {
        title: 'New Arrivals',
        description: 'Fresh drops, sharp fits, and the latest HyperFit silhouettes just added to the collection.',
        breadcrumbs: [
          { label: 'Home', to: '/' },
          { label: 'Collections', to: '/shop' },
          { label: 'New Arrivals' }
        ]
      };
    }

    if (filters.search) {
      return {
        title: 'Search Results',
        description: `Showing HyperFit results for "${filters.search}".`,
        breadcrumbs: [
          { label: 'Home', to: '/' },
          { label: 'Collections', to: '/shop' },
          { label: 'Search Results' }
        ]
      };
    }

    if (filters.fit) {
      return {
        title: `${filters.fit} Fit`,
        description: `${filters.fit} silhouettes selected from the current HyperFit catalogue.`,
        breadcrumbs: [
          { label: 'Home', to: '/' },
          { label: 'Collections', to: '/shop' },
          { label: `${filters.fit} Fit` }
        ]
      };
    }

    return defaultContext;
  }, [activeCategory, activeRootCategory, filters.fit, filters.new_arrival, filters.sale, filters.search]);

  useEffect(() => {
    setMeta({
      title: `${pageContext.title} | HyperFit`,
      description: pageContext.description
    });
  }, [pageContext.description, pageContext.title]);

  const resultSummary = useMemo(() => {
    if (catalogMeta.total > catalogProducts.length) {
      return `Showing ${visibleProducts.length} of ${catalogMeta.total} items available in this collection.`;
    }

    if (visibleProducts.length !== catalogProducts.length) {
      return `Filtered to ${visibleProducts.length} items from ${catalogProducts.length} available styles.`;
    }

    return `${visibleProducts.length} products ready to browse right now.`;
  }, [catalogMeta.total, catalogProducts.length, visibleProducts.length]);

  const activeFilterPills = useMemo(() => {
    const pills = [];

    effectiveCategorySlugs.forEach((slug) => {
      const category = categoriesBySlug.get(slug);
      if (category) {
        pills.push({ type: 'category', value: slug, label: category.name });
      }
    });

    filters.brands.forEach((item) => pills.push({ type: 'brand', value: item, label: item }));
    filters.sizes.forEach((item) => pills.push({ type: 'size', value: item, label: `Size ${item}` }));
    filters.colors.forEach((item) => pills.push({ type: 'color', value: item, label: item }));
    filters.materials.forEach((item) => pills.push({ type: 'material', value: item, label: item }));

    if (filters.fit) pills.push({ type: 'fit', value: filters.fit, label: `${filters.fit} Fit` });
    if (filters.min_price || filters.max_price) {
      pills.push({
        type: 'price',
        value: 'price',
        label: `${inr(selectedPriceMin)} - ${inr(selectedPriceMax)}`
      });
    }

    return pills;
  }, [
    categoriesBySlug,
    effectiveCategorySlugs,
    filters.brands,
    filters.colors,
    filters.fit,
    filters.materials,
    filters.min_price,
    filters.max_price,
    filters.sizes,
    selectedPriceMax,
    selectedPriceMin
  ]);

  const sortLabel = SORT_OPTIONS.find((option) => option.value === filters.sort)?.label || 'Featured';
  const fitLabel = filters.fit ? `${filters.fit} Fit` : 'Fit';

  const toggleListFilter = (key, value) => {
    setFilters((prev) => {
      const current = prev[key];
      const exists = current.includes(value);
      return {
        ...prev,
        [key]: exists ? current.filter((item) => item !== value) : [...current, value]
      };
    });
  };

  const toggleCategory = (slug) => {
    setFilters((prev) => {
      const base = prev.categories.length ? prev.categories : (activeCategory?.parent_id ? [activeCategory.slug] : []);
      const exists = base.includes(slug);

      if (exists && base.length === 1 && activeCategory?.parent_id && activeRootCategory && base[0] === slug) {
        return {
          ...prev,
          category: activeRootCategory.slug,
          categories: []
        };
      }

      return {
        ...prev,
        categories: exists ? base.filter((item) => item !== slug) : [...base, slug]
      };
    });
  };

  const setPriceValue = (key, nextValue) => {
    const value = Number(nextValue);

    if (key === 'min_price') {
      const clamped = Math.min(value, selectedPriceMax);
      setFilters((prev) => ({
        ...prev,
        min_price: clamped <= priceBounds.min ? '' : String(clamped)
      }));
      return;
    }

    const clamped = Math.max(value, selectedPriceMin);
    setFilters((prev) => ({
      ...prev,
      max_price: clamped >= priceBounds.max ? '' : String(clamped)
    }));
  };

  const clearFacetFilters = () => {
    setFilters((prev) => ({
      ...prev,
      categories: [],
      brands: [],
      sizes: [],
      colors: [],
      materials: [],
      fit: '',
      min_price: '',
      max_price: ''
    }));
  };

  const removePill = (pill) => {
    if (pill.type === 'category') {
      if (!filters.categories.length && activeCategory?.parent_id && activeRootCategory && pill.value === activeCategory.slug) {
        setFilters((prev) => ({
          ...prev,
          category: activeRootCategory.slug,
          categories: []
        }));
        return;
      }

      setFilters((prev) => ({
        ...prev,
        categories: prev.categories.filter((item) => item !== pill.value)
      }));
      return;
    }

    if (pill.type === 'price') {
      setFilters((prev) => ({ ...prev, min_price: '', max_price: '' }));
      return;
    }

    if (pill.type === 'fit') {
      setFilters((prev) => ({ ...prev, fit: '' }));
      return;
    }

    const keyMap = {
      brand: 'brands',
      size: 'sizes',
      color: 'colors',
      material: 'materials'
    };

    const listKey = keyMap[pill.type];
    if (!listKey) return;

    setFilters((prev) => ({
      ...prev,
      [listKey]: prev[listKey].filter((item) => item !== pill.value)
    }));
  };

  const toggleFilterPanel = () => {
    if (window.matchMedia('(max-width: 1040px)').matches) {
      setMobileFilterOpen(true);
      return;
    }

    setDesktopFiltersOpen((prev) => !prev);
  };

  const filterPanel = (
    <div className="shop-sidebar-card">
      <div className="shop-filter-header">
        <div>
          <p>Refine Selection</p>
          <strong>{visibleProducts.length} styles</strong>
        </div>
        <button type="button" className="text-link" onClick={clearFacetFilters}>Clear</button>
      </div>

      <div className="shop-search-field">
        <label>Search within this collection</label>
        <input
          type="search"
          aria-label="Search within this collection"
          value={searchInput}
          onChange={(event) => setSearchInput(event.target.value)}
          placeholder="Search products or collections"
        />
      </div>

      <FilterSection title="Categories">
        <div className="shop-check-list">
          {categoryOptions.length ? categoryOptions.map((item) => (
            <button
              key={item.slug}
              type="button"
              className={`shop-check-option ${effectiveCategorySlugs.includes(item.slug) ? 'active' : ''}`}
              onClick={() => toggleCategory(item.slug)}
              aria-pressed={effectiveCategorySlugs.includes(item.slug)}
            >
              <span>{item.name}</span>
              <small>{categoryCounts[item.slug] || 0}</small>
            </button>
          )) : <p className="shop-filter-empty">Categories will appear when products are available.</p>}
        </div>
      </FilterSection>

      <FilterSection title="Brand">
        <div className="shop-check-list">
          {brandOptions.map((brand) => (
            <button
              key={brand}
              type="button"
              className={`shop-check-option ${filters.brands.includes(brand) ? 'active' : ''}`}
              onClick={() => toggleListFilter('brands', brand)}
              aria-pressed={filters.brands.includes(brand)}
            >
              <span>{brand}</span>
            </button>
          ))}
        </div>
      </FilterSection>

      <FilterSection title="Size">
        <div className="shop-chip-group">
          {sizeOptions.map((size) => (
            <button
              key={size}
              type="button"
              className={`shop-filter-chip ${filters.sizes.includes(size) ? 'active' : ''}`}
              onClick={() => toggleListFilter('sizes', size)}
              aria-pressed={filters.sizes.includes(size)}
            >
              {size}
            </button>
          ))}
        </div>
      </FilterSection>

      <FilterSection title="Price">
        <div className="shop-range-block">
          <div className="shop-range-values">
            <strong>{inr(selectedPriceMin)}</strong>
            <span>to</span>
            <strong>{inr(selectedPriceMax)}</strong>
          </div>
          <div className="shop-range-slider">
            <input
              type="range"
              min={priceBounds.min}
              max={priceBounds.max}
              step={priceStep}
              value={selectedPriceMin}
              onChange={(event) => setPriceValue('min_price', event.target.value)}
              aria-label="Minimum price"
            />
            <input
              type="range"
              min={priceBounds.min}
              max={priceBounds.max}
              step={priceStep}
              value={selectedPriceMax}
              onChange={(event) => setPriceValue('max_price', event.target.value)}
              aria-label="Maximum price"
            />
          </div>
        </div>
      </FilterSection>

      <FilterSection title="Color">
        <div className="shop-swatch-grid">
          {colorOptions.map((color) => (
            <button
              key={color}
              type="button"
              className={`shop-swatch ${filters.colors.includes(color) ? 'active' : ''}`}
              style={{ '--swatch-color': resolveColorSwatch(color) }}
              onClick={() => toggleListFilter('colors', color)}
              aria-label={`Filter by ${color}`}
              aria-pressed={filters.colors.includes(color)}
              title={color}
            >
              <span />
            </button>
          ))}
        </div>
      </FilterSection>

      {materialOptions.length ? (
        <FilterSection title="Material">
          <div className="shop-chip-group">
            {materialOptions.map((material) => (
              <button
                key={material}
                type="button"
                className={`shop-filter-chip ${filters.materials.includes(material) ? 'active' : ''}`}
                onClick={() => toggleListFilter('materials', material)}
                aria-pressed={filters.materials.includes(material)}
              >
                {material}
              </button>
            ))}
          </div>
        </FilterSection>
      ) : null}
    </div>
  );

  return (
    <div className="hf-container page-gap shop-page">
      <Reveal as="section" className="shop-shell" threshold={0.08}>
        <header className="shop-topline">
          <nav className="shop-breadcrumbs" aria-label="Breadcrumb">
            {pageContext.breadcrumbs.map((item, index) => (
              <span key={`${item.label}-${index}`}>
                {item.to ? <Link to={item.to}>{item.label}</Link> : <span aria-current="page">{item.label}</span>}
                {index < pageContext.breadcrumbs.length - 1 ? <span className="shop-breadcrumb-divider">/</span> : null}
              </span>
            ))}
          </nav>

          <div className="shop-title-row">
            <div>
              <h1>{pageContext.title}</h1>
              <p>{pageContext.description}</p>
            </div>

            <div className="shop-result-summary" aria-label="Result count">
              <strong>{visibleProducts.length}</strong>
              <span>Results</span>
            </div>
          </div>
        </header>

        <div className="shop-toolbar" role="toolbar" aria-label="Catalog controls">
          <button type="button" className="shop-control-button" onClick={toggleFilterPanel} aria-label="Open filters">
            <ToolbarIcon type="filter" />
            <span>{desktopFiltersOpen ? 'Filters' : 'Filter'}</span>
          </button>

          <div className={`shop-control-menu ${sortMenuOpen ? 'open' : ''}`}>
            <button
              type="button"
              className="shop-control-button"
              onClick={() => {
                setSortMenuOpen((prev) => !prev);
                setFitMenuOpen(false);
              }}
              aria-expanded={sortMenuOpen}
              aria-label={`Sort products, currently ${sortLabel}`}
            >
              <ToolbarIcon type="sort" />
              <span>Sort: {sortLabel}</span>
            </button>

            <div className="shop-control-panel" role="menu" aria-label="Sort products">
              {SORT_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  className={`shop-control-option ${filters.sort === option.value ? 'active' : ''}`}
                  onClick={() => {
                    setFilters((prev) => ({ ...prev, sort: option.value }));
                    setSortMenuOpen(false);
                  }}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          <div className={`shop-control-menu ${fitMenuOpen ? 'open' : ''}`}>
            <button
              type="button"
              className="shop-control-button"
              onClick={() => {
                setFitMenuOpen((prev) => !prev);
                setSortMenuOpen(false);
              }}
              aria-expanded={fitMenuOpen}
              aria-label={`Filter by fit, currently ${fitLabel}`}
            >
              <ToolbarIcon type="fit" />
              <span>{fitLabel}</span>
            </button>

            <div className="shop-control-panel" role="menu" aria-label="Choose fit">
              <button
                type="button"
                className={`shop-control-option ${!filters.fit ? 'active' : ''}`}
                onClick={() => {
                  setFilters((prev) => ({ ...prev, fit: '' }));
                  setFitMenuOpen(false);
                }}
              >
                All Fits
              </button>
              {fitOptions.map((option) => (
                <button
                  key={option}
                  type="button"
                  className={`shop-control-option ${filters.fit === option ? 'active' : ''}`}
                  onClick={() => {
                    setFilters((prev) => ({ ...prev, fit: prev.fit === option ? '' : option }));
                    setFitMenuOpen(false);
                  }}
                >
                  {option}
                </button>
              ))}
            </div>
          </div>

          <p className="shop-toolbar-results"><strong>{visibleProducts.length}</strong> Results</p>
        </div>

        {activeFilterPills.length ? (
          <div className="shop-active-filters" aria-label="Active filters">
            {activeFilterPills.map((pill) => (
              <button key={`${pill.type}-${pill.value}`} type="button" className="shop-active-pill" onClick={() => removePill(pill)}>
                <span>{pill.label}</span>
                <small>x</small>
              </button>
            ))}
          </div>
        ) : null}

        <div className={`shop-layout ${desktopFiltersOpen ? '' : 'filters-collapsed'}`}>
          <aside className={`shop-sidebar ${desktopFiltersOpen ? '' : 'is-collapsed'}`} aria-label="Product filters">
            {filterPanel}
          </aside>

          <section className="shop-results-panel" aria-live="polite">
            <div className="shop-results-head">
              <p>{resultSummary}</p>
              {filters.category || filters.sale || filters.new_arrival || filters.search ? (
                <Link className="text-link" to="/shop">View All Collections</Link>
              ) : null}
            </div>

            {error ? (
              <div className="shop-empty-state">
                <h3>Something went wrong</h3>
                <p>{error}</p>
                <button type="button" onClick={() => setRequestKey((prev) => prev + 1)}>Try Again</button>
              </div>
            ) : null}

            {!error && loading ? (
              <SkeletonLoader rows={8} variant="cards" />
            ) : null}

            {!error && !loading && !visibleProducts.length ? (
              <div className="shop-empty-state">
                <h3>No products match this selection</h3>
                <p>Adjust the filters or clear the current refinements to see more styles.</p>
                <button type="button" onClick={clearFacetFilters}>Reset Filters</button>
              </div>
            ) : null}

            {!error && !loading && visibleProducts.length ? (
              <div className="product-grid">
                {visibleProducts.map((item, index) => (
                  <Reveal key={item.id} delay={index * 0.03} threshold={0.08}>
                    <ProductCard product={item} />
                  </Reveal>
                ))}
              </div>
            ) : null}
          </section>
        </div>
      </Reveal>

      <div className={`shop-mobile-sheet ${mobileFilterOpen ? 'open' : ''}`}>
        <button className="sheet-backdrop" onClick={() => setMobileFilterOpen(false)} aria-label="Close filter panel" />
        <div className="sheet-content">
          <div className="sheet-head">
            <div>
              <h3>Filters</h3>
              <p>{visibleProducts.length} results</p>
            </div>
            <button type="button" onClick={() => setMobileFilterOpen(false)}>Close</button>
          </div>
          {filterPanel}
        </div>
      </div>
    </div>
  );
}

export default Shop;
