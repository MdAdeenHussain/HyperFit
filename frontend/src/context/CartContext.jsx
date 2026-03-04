import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { cartService } from '../services/cartService';
import { useAuth } from './AuthContext';

const CartContext = createContext(null);

function getGuestCart() {
  try {
    return JSON.parse(localStorage.getItem('hf_guest_cart') || '[]');
  } catch {
    return [];
  }
}

export function CartProvider({ children }) {
  const { user } = useAuth();
  const [items, setItems] = useState([]);

  const loadCart = async () => {
    if (!user) {
      setItems(getGuestCart());
      return;
    }

    const guestItems = getGuestCart();
    if (guestItems.length) {
      for (const item of guestItems) {
        await cartService.addItem(item);
      }
      localStorage.removeItem('hf_guest_cart');
    }

    const { data } = await cartService.getCart();
    setItems(data.items || []);
  };

  useEffect(() => {
    loadCart();
  }, [user]);

  const summary = useMemo(() => {
    if (!items.length) return { subtotal: 0, count: 0 };
    if (user) {
      const subtotal = items.filter((i) => !i.saved_for_later).reduce((sum, i) => sum + i.product.price * i.quantity, 0);
      return { subtotal, count: items.length };
    }
    const subtotal = items.reduce((sum, i) => sum + Number(i.price || 0) * Number(i.quantity || 1), 0);
    return { subtotal, count: items.length };
  }, [items, user]);

  const value = useMemo(
    () => ({
      items,
      summary,
      async addToCart(payload) {
        if (!user) {
          const next = [...getGuestCart(), payload];
          localStorage.setItem('hf_guest_cart', JSON.stringify(next));
          setItems(next);
          return;
        }
        await cartService.addItem(payload);
        await loadCart();
      },
      async updateCart(itemId, payload) {
        if (!user) return;
        await cartService.updateItem(itemId, payload);
        await loadCart();
      },
      async removeCart(itemId) {
        if (!user) return;
        await cartService.removeItem(itemId);
        await loadCart();
      },
      refreshCart: loadCart
    }),
    [items, summary, user]
  );

  return <CartContext.Provider value={value}>{children}</CartContext.Provider>;
}

export function useCart() {
  const ctx = useContext(CartContext);
  if (!ctx) throw new Error('useCart must be used within CartProvider');
  return ctx;
}
