import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useCart } from '../context/CartContext';
import { cartService } from '../services/cartService';
import { inr } from '../utils/helpers';

function Cart() {
  const { items, summary, updateCart, removeCart } = useCart();
  const [coupon, setCoupon] = useState('');
  const [couponResult, setCouponResult] = useState(null);
  const [pincode, setPincode] = useState('');
  const [shipping, setShipping] = useState(null);

  const applyCoupon = async () => {
    const { data } = await cartService.applyCoupon(coupon);
    setCouponResult(data);
  };

  const estimateShipping = async () => {
    const { data } = await cartService.shippingEstimate(pincode);
    setShipping(data);
  };

  return (
    <div className="hf-container page-gap">
      <h1>Cart</h1>

      <div className="cart-layout">
        <section>
          {items.map((item) => (
            <article key={item.id || `${item.product_id}-${item.size}-${item.color}`} className="cart-item">
              <img loading="lazy" src={item.product?.image || '/placeholder.png'} alt={item.product?.name || 'Product'} />
              <div>
                <h4>{item.product?.name || `Product ${item.product_id}`}</h4>
                <p>{inr(item.product?.price || item.price)}</p>
                <small>{item.size || '-'} / {item.color || '-'}</small>
              </div>
              {item.id ? (
                <input type="number" min="1" value={item.quantity} onChange={(e) => updateCart(item.id, { quantity: Number(e.target.value) })} />
              ) : (
                <span>Qty: {item.quantity}</span>
              )}
              {item.id ? (
                <button onClick={() => updateCart(item.id, { saved_for_later: !item.saved_for_later })}>{item.saved_for_later ? 'Move to cart' : 'Save for later'}</button>
              ) : null}
              {item.id ? <button onClick={() => removeCart(item.id)}>Remove</button> : null}
            </article>
          ))}
        </section>

        <aside className="summary-card">
          <h3>Summary</h3>
          <p>Subtotal: {inr(summary.subtotal)}</p>

          <div className="inline">
            <input placeholder="Coupon code" value={coupon} onChange={(e) => setCoupon(e.target.value)} />
            <button onClick={applyCoupon}>Apply</button>
          </div>
          {couponResult && <p>Discount: {inr(couponResult.discount)} | Payable: {inr(couponResult.payable)}</p>}

          <div className="inline">
            <input placeholder="Pincode" value={pincode} onChange={(e) => setPincode(e.target.value)} />
            <button onClick={estimateShipping}>Estimate</button>
          </div>
          {shipping && <p>{shipping.eta_days} days · Fee {inr(shipping.shipping_fee)}</p>}

          <p>Free delivery above admin-defined threshold.</p>
          <Link className="solid-link" to="/checkout">Proceed to Checkout</Link>
        </aside>
      </div>
    </div>
  );
}

export default Cart;
