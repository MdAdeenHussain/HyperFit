import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import { orderService } from '../services/orderService';

function Checkout() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  const [step, setStep] = useState(1);
  const [addresses, setAddresses] = useState([]);
  const [addressId, setAddressId] = useState('');
  const [couponCode, setCouponCode] = useState('');
  const [shippingRate, setShippingRate] = useState(null);
  const [paymentMethod, setPaymentMethod] = useState('razorpay');

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
      return;
    }

    async function loadAddresses() {
      const { data } = await api.get('/user/addresses');
      setAddresses(data.items || []);
      if (data.items?.length) setAddressId(data.items[0].id);
    }
    loadAddresses();
  }, [isAuthenticated]);

  const placeOrder = async () => {
    const { data } = await orderService.checkout({ address_id: Number(addressId), coupon_code: couponCode });
    const orderNumber = data.order.order_number;
    const paymentData = await orderService.createPayment({ order_number: orderNumber });

    if (paymentMethod === 'cod') {
      await orderService.verifyPayment({
        order_number: orderNumber,
        provider_order_id: paymentData.data.razorpay_order.id,
        provider_payment_id: `cod_${Date.now()}`,
        signature: 'cod_signature'
      });
    }

    navigate('/account');
  };

  return (
    <div className="hf-container page-gap">
      <h1>Checkout</h1>

      <div className="checkout-steps">
        {[1, 2, 3, 4, 5].map((s) => <button key={s} className={step === s ? 'active' : ''} onClick={() => setStep(s)}>Step {s}</button>)}
      </div>

      {step === 1 && <section className="card-block"><h3>Login Required</h3><p>Authenticated checkout enabled.</p><button onClick={() => setStep(2)}>Continue</button></section>}

      {step === 2 && (
        <section className="card-block">
          <h3>Address Management</h3>
          <select value={addressId} onChange={(e) => setAddressId(e.target.value)}>
            {addresses.map((address) => <option key={address.id} value={address.id}>{address.name} - {address.city}</option>)}
          </select>
          <button onClick={() => setStep(3)}>Continue</button>
        </section>
      )}

      {step === 3 && (
        <section className="card-block">
          <h3>Shipping Partner</h3>
          <button onClick={async () => {
            const a = addresses.find((item) => String(item.id) === String(addressId));
            const { data } = await api.post('/shipping/rates', { pincode: a?.pincode, weight: 0.5 });
            setShippingRate(data.rates?.[0]);
          }}>Fetch ShipRocket Rates</button>
          {shippingRate && <p>{shippingRate.partner} · INR {shippingRate.amount} · ETA {shippingRate.eta_days} days</p>}
          <button onClick={() => setStep(4)}>Continue</button>
        </section>
      )}

      {step === 4 && (
        <section className="card-block">
          <h3>Payment Selection</h3>
          <select value={paymentMethod} onChange={(e) => setPaymentMethod(e.target.value)}>
            <option value="razorpay">Razorpay (Cards/UPI/NetBanking/Wallets)</option>
            <option value="cod">Cash on Delivery</option>
          </select>
          <button onClick={() => setStep(5)}>Continue</button>
        </section>
      )}

      {step === 5 && (
        <section className="card-block">
          <h3>Apply Coupon</h3>
          <input placeholder="Coupon code" value={couponCode} onChange={(e) => setCouponCode(e.target.value)} />
          <button onClick={placeOrder}>Place Order</button>
        </section>
      )}
    </div>
  );
}

export default Checkout;
