export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000/api';

export const NAV_LINKS = [
  { label: 'Men', path: '/shop?category=men' },
  { label: 'Women', path: '/shop?category=women' },
  { label: 'New Arrivals', path: '/shop?sort=new' },
  { label: 'On Sale', path: '/shop?sale=true' }
];

export const MEN_CATEGORIES = ['T-Shirts', 'Compression', 'Pants', 'Shorts'];
export const WOMEN_CATEGORIES = ['Sports Bra', 'Leggings', 'T-Shirts'];

export const SORT_OPTIONS = [
  { label: 'Price Low to High', value: 'price_asc' },
  { label: 'Price High to Low', value: 'price_desc' },
  { label: 'New Arrivals', value: 'new' },
  { label: 'Best Selling', value: 'best_selling' }
];
