import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import { orderService } from '../services/orderService';
import Reveal from '../components/Reveal';

const STEP_CONFIG = [
  { id: 1, label: 'Login' },
  { id: 2, label: 'Shipping Address' },
  { id: 3, label: 'Shipping Rate' },
  { id: 4, label: 'Payment' },
  { id: 5, label: 'Confirmation' }
];

function Checkout() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  const [step, setStep] = useState(1);
  const [addresses, setAddresses] = useState([]);
  const [addressId, setAddressId] = useState('');
  const [couponCode, setCouponCode] = useState('');
  const [shippingRate, setShippingRate] = useState(null);
  const [paymentMethod, setPaymentMethod] = useState('razorpay');
  const [placing, setPlacing] = useState(false);

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
  }, [isAuthenticated, navigate]);

  const progress = useMemo(() => `${((step - 1) / (STEP_CONFIG.length - 1)) * 100}%`, [step]);

  const placeOrder = async () => {
    setPlacing(true);
    try {
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
    } finally {
      setPlacing(false);
    }
  };

  return (
    <div className="hf-container page-gap checkout-page">
      <Reveal threshold={0.1}><h1>Checkout</h1></Reveal>

      <div className="checkout-progress-track" role="presentation">
        <span style={{ width: progress }} />
      </div>

      <div className="checkout-steps">
        {STEP_CONFIG.map((item) => (
          <button key={item.id} className={step === item.id ? 'active' : ''} onClick={() => setStep(item.id)}>{item.label}</button>
        ))}
      </div>

      {step === 1 && <Reveal as="section" className="card-block checkout-step-card"><h3>Login</h3><p>Authenticated checkout enabled.</p><button onClick={() => setStep(2)}>Continue</button></Reveal>}

      {step === 2 && (
        <Reveal as="section" className="card-block checkout-step-card">
          <h3>Shipping Address</h3>
          <select value={addressId} onChange={(event) => setAddressId(event.target.value)}>
            {addresses.map((address) => <option key={address.id} value={address.id}>{address.name} - {address.city}</option>)}
          </select>
          <button onClick={() => setStep(3)}>Continue</button>
        </Reveal>
      )}

      {step === 3 && (
        <Reveal as="section" className="card-block checkout-step-card">
          <h3>Shipping Rate</h3>
          <button onClick={async () => {
            const selected = addresses.find((item) => String(item.id) === String(addressId));
            const { data } = await api.post('/shipping/rates', { pincode: selected?.pincode, weight: 0.5 });
            setShippingRate(data.rates?.[0]);
          }}>Fetch ShipRocket Rates</button>
          {shippingRate && <p>{shippingRate.partner} · INR {shippingRate.amount} · ETA {shippingRate.eta_days} days</p>}
          <button onClick={() => setStep(4)}>Continue</button>
        </Reveal>
      )}

      {step === 4 && (
        <Reveal as="section" className="card-block checkout-step-card">
          <h3>Payment</h3>
          <select value={paymentMethod} onChange={(event) => setPaymentMethod(event.target.value)}>
            <option value="razorpay">Razorpay (Cards/UPI/NetBanking/Wallets)</option>
            <option value="cod">Cash on Delivery</option>
          </select>
          <button onClick={() => setStep(5)}>Continue</button>
        </Reveal>
      )}

      {step === 5 && (
        <Reveal as="section" className="card-block checkout-step-card">
          <h3>Confirmation</h3>
          <input placeholder="Coupon code" value={couponCode} onChange={(event) => setCouponCode(event.target.value)} />
          <button onClick={placeOrder} disabled={placing}>{placing ? 'Placing...' : 'Place Order'}</button>
        </Reveal>
      )}
    </div>
  );
}

export default Checkout;
