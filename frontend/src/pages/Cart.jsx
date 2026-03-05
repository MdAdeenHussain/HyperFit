import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useCart } from '../context/CartContext';
import { cartService } from '../services/cartService';
import { inr } from '../utils/helpers';
import Reveal from '../components/Reveal';

function Cart() {
  const { items, summary, updateCart, removeCart } = useCart();
  const [coupon, setCoupon] = useState('');
  const [couponResult, setCouponResult] = useState(null);
  const [pincode, setPincode] = useState('');
  const [shipping, setShipping] = useState(null);
  const [updatingId, setUpdatingId] = useState(null);
  const [subtotalPulse, setSubtotalPulse] = useState(false);

  useEffect(() => {
    setSubtotalPulse(true);
    const timeout = window.setTimeout(() => setSubtotalPulse(false), 400);
    return () => window.clearTimeout(timeout);
  }, [summary.subtotal]);

  const applyCoupon = async () => {
    const { data } = await cartService.applyCoupon(coupon);
    setCouponResult(data);
  };

  const estimateShipping = async () => {
    const { data } = await cartService.shippingEstimate(pincode);
    setShipping(data);
  };

  const onQuantityChange = async (itemId, quantity) => {
    setUpdatingId(itemId);
    try {
      await updateCart(itemId, { quantity });
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="hf-container page-gap cart-page">
      <Reveal threshold={0.1}><h1>Cart</h1></Reveal>

      <div className="cart-layout">
        <Reveal as="section" threshold={0.12}>
          {items.map((item, index) => (
            <article key={item.id || `${item.product_id}-${item.size}-${item.color}`} className={`cart-item ${updatingId === item.id ? 'is-updating' : ''}`} style={{ '--item-delay': `${index * 0.04}s` }}>
              <img loading="lazy" src={item.product?.image || '/placeholder.png'} alt={item.product?.name || 'Product'} />
              <div>
                <h4>{item.product?.name || `Product ${item.product_id}`}</h4>
                <p>{inr(item.product?.price || item.price)}</p>
                <small>{item.size || '-'} / {item.color || '-'}</small>
              </div>
              {item.id ? (
                <input type="number" min="1" value={item.quantity} onChange={(event) => onQuantityChange(item.id, Number(event.target.value))} />
              ) : (
                <span>Qty: {item.quantity}</span>
              )}
              {item.id ? (
                <button onClick={() => updateCart(item.id, { saved_for_later: !item.saved_for_later })}>{item.saved_for_later ? 'Move to cart' : 'Save for later'}</button>
              ) : null}
              {item.id ? <button onClick={() => removeCart(item.id)}>Remove</button> : null}
            </article>
          ))}
        </Reveal>

        <Reveal as="aside" className="summary-card" delay={0.08} threshold={0.12}>
          <h3>Summary</h3>
          <p className={subtotalPulse ? 'subtotal-pop' : ''}>Subtotal: {inr(summary.subtotal)}</p>

          <div className="inline">
            <input placeholder="Coupon code" value={coupon} onChange={(event) => setCoupon(event.target.value)} />
            <button onClick={applyCoupon}>Apply</button>
          </div>
          {couponResult && <p>Discount: {inr(couponResult.discount)} | Payable: {inr(couponResult.payable)}</p>}

          <div className="inline">
            <input placeholder="Pincode" value={pincode} onChange={(event) => setPincode(event.target.value)} />
            <button onClick={estimateShipping}>Estimate</button>
          </div>
          {shipping && <p>{shipping.eta_days} days · Fee {inr(shipping.shipping_fee)}</p>}

          <p>Free delivery above admin-defined threshold.</p>
          <Link className="solid-link" to="/checkout">Proceed to Checkout</Link>
        </Reveal>
      </div>
    </div>
  );
}

export default Cart;
