export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000/api';

export const NAV_LINKS = [
  { label: 'Men', path: '/shop?category=men' },
  { label: 'Women', path: '/shop?category=women' },
  { label: 'Compression', path: '/shop?category=compression' },
  { label: 'New Arrivals 🔥', path: '/shop?new_arrival=true&sort=new' },
  { label: 'Sale', path: '/shop?sale=true' },
  { label: 'Accessories', path: '/shop?search=accessories' }
];

export const MEN_CATEGORIES = ['T-Shirts', 'Compression', 'Pants', 'Shorts'];
export const WOMEN_CATEGORIES = ['Sports Bra', 'Leggings', 'T-Shirts'];

export const SORT_OPTIONS = [
  { label: 'Price Low to High', value: 'price_asc' },
  { label: 'Price High to Low', value: 'price_desc' },
  { label: 'New Arrivals', value: 'new' },
  { label: 'Best Selling', value: 'best_selling' }
];
