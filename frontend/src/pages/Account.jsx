import { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import api from '../services/api';
import { setMeta } from '../utils/helpers';
import { ACCOUNT_NAV_GROUPS } from '../account/accountNav';
import AccountHeader from '../account/components/AccountHeader';
import AccountSidebar from '../account/components/AccountSidebar';
import AccountOverview from '../account/components/AccountOverview';
import OrdersPanel from '../account/components/OrdersPanel';
import ProfileCard from '../account/components/ProfileCard';
import CouponsPanel from '../account/components/CouponsPanel';
import AddressesPanel from '../account/components/AddressesPanel';
import NewsletterPreferencesPanel from '../account/components/NewsletterPreferencesPanel';
import ThemeSelector from '../account/components/ThemeSelector';
import DeleteAccountPanel from '../account/components/DeleteAccountPanel';
import PlaceholderPanel from '../account/components/PlaceholderPanel';
import AccountSkeleton from '../account/components/AccountSkeleton';

function profileMetaKey(userId) {
  return `hf_profile_meta_${userId}`;
}

function parseFullName(fullName = '') {
  const trimmed = fullName.trim();
  if (!trimmed) return { first_name: '', last_name: '' };
  const [first, ...rest] = trimmed.split(/\s+/);
  return {
    first_name: first || '',
    last_name: rest.join(' ') || '-'
  };
}

function formatCouponDate(date) {
  return date.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
}

function Account() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user, refreshProfile, logout } = useAuth();
  const { theme, setTheme } = useTheme();

  const [loading, setLoading] = useState(true);
  const [orders, setOrders] = useState([]);
  const [addresses, setAddresses] = useState([]);
  const [wishlistCount, setWishlistCount] = useState(0);
  const [featuredProducts, setFeaturedProducts] = useState([]);
  const [profileMeta, setProfileMeta] = useState({
    gender: '',
    dateOfBirth: '',
    location: '',
    alternateMobile: '',
    hintName: ''
  });
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [newsletterSaving, setNewsletterSaving] = useState(false);
  const [newsletterMessage, setNewsletterMessage] = useState('');
  const [newsletterStatus, setNewsletterStatus] = useState('idle');
  const [newsletterSubscribed, setNewsletterSubscribed] = useState(Boolean(user?.newsletter_subscribed));

  const activeTab = searchParams.get('tab') || 'overview';
  const isDark = theme === 'dark';

  useEffect(() => {
    setMeta({
      title: 'My Account | HyperFit',
      description: 'Manage your profile, orders, credits, addresses, preferences and account settings.'
    });
  }, []);

  const loadAccountData = async () => {
    if (!user) return;

    setLoading(true);
    try {
      const [ordersRes, addressesRes, wishlistRes, featuredRes] = await Promise.all([
        api.get('/user/orders'),
        api.get('/user/addresses'),
        api.get('/user/wishlist'),
        api.get('/products/featured')
      ]);

      setOrders(ordersRes.data.items || []);
      setAddresses(addressesRes.data.items || []);
      setWishlistCount((wishlistRes.data.items || []).length);
      setFeaturedProducts(featuredRes.data.items || []);

      const storedMeta = JSON.parse(localStorage.getItem(profileMetaKey(user.id)) || '{}');
      setProfileMeta((prev) => ({ ...prev, ...storedMeta }));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAccountData();
  }, [user]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    setNewsletterSubscribed(Boolean(user?.newsletter_subscribed));
  }, [user?.newsletter_subscribed]);

  const couponData = useMemo(() => {
    const discounts = [10, 15, 20, 12, 18, 25, 14, 22];
    const minimums = [999, 1199, 1499, 899, 1299, 1799, 1099, 1999];

    const source = featuredProducts.length ? featuredProducts : Array.from({ length: 6 }).map((_, index) => ({
      id: index + 1,
      name: `HyperFit Offer ${index + 1}`,
      images: ['/placeholder.png']
    }));

    return source.map((item, index) => {
      const discount = discounts[index % discounts.length];
      const expiryDate = new Date(Date.now() + (index + 8) * 24 * 60 * 60 * 1000);
      return {
        id: item.id,
        image: item.images?.[0] || '/placeholder.png',
        title: `Flat ${discount}% OFF`,
        minimumText: `On min. purchase of ₹${minimums[index % minimums.length]}`,
        code: `HF${(item.slug || item.name || 'DEAL').replace(/[^A-Z0-9]/gi, '').slice(0, 5).toUpperCase()}${100 + index}`,
        expiryDate,
        expiryLabel: formatCouponDate(expiryDate),
        discount,
        trendingScore: Math.max(20, 100 - index * 8)
      };
    });
  }, [featuredProducts]);

  const profile = useMemo(() => ({
    fullName: `${user?.first_name || ''} ${user?.last_name || ''}`.trim(),
    mobile: user?.phone || '',
    email: user?.email || '',
    gender: profileMeta.gender || '',
    dateOfBirth: profileMeta.dateOfBirth || '',
    location: profileMeta.location || '',
    alternateMobile: profileMeta.alternateMobile || '',
    hintName: profileMeta.hintName || ''
  }), [profileMeta, user]);

  const stats = useMemo(() => ([
    { label: 'Total Orders', value: orders.length },
    { label: 'Wishlist Items', value: wishlistCount },
    { label: 'Saved Addresses', value: addresses.length },
    { label: 'Active Coupons', value: couponData.length }
  ]), [orders.length, wishlistCount, addresses.length, couponData.length]);

  const activeLabel = useMemo(() => {
    const items = ACCOUNT_NAV_GROUPS.flatMap((group) => group.items);
    const match = items.find((item) => item.key === activeTab);
    return match?.label || 'Overview';
  }, [activeTab]);

  const setActiveTab = (tab) => {
    if (tab === 'logout') {
      logout().then(() => navigate('/'));
      return;
    }
    setSearchParams({ tab });
  };

  const downloadInvoice = async (orderNumber) => {
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000/api'}/orders/${orderNumber}/invoice`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('hf_access_token')}` }
    });
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `invoice_${orderNumber}.pdf`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const saveProfile = async (nextProfile) => {
    const { first_name, last_name } = parseFullName(nextProfile.fullName);

    await api.put('/user/account', {
      first_name,
      last_name,
      phone: nextProfile.mobile
    });

    localStorage.setItem(profileMetaKey(user.id), JSON.stringify({
      gender: nextProfile.gender,
      dateOfBirth: nextProfile.dateOfBirth,
      location: nextProfile.location,
      alternateMobile: nextProfile.alternateMobile,
      hintName: nextProfile.hintName
    }));

    setProfileMeta({
      gender: nextProfile.gender,
      dateOfBirth: nextProfile.dateOfBirth,
      location: nextProfile.location,
      alternateMobile: nextProfile.alternateMobile,
      hintName: nextProfile.hintName
    });

    await refreshProfile();
  };

  const updateNewsletterPreference = async (subscribed) => {
    const previousValue = newsletterSubscribed;
    setNewsletterSubscribed(subscribed);
    setNewsletterSaving(true);
    setNewsletterMessage('');
    setNewsletterStatus('idle');

    try {
      const { data } = await api.put('/user/account/newsletter', { subscribed });
      setNewsletterSubscribed(Boolean(data.subscribed));
      setNewsletterMessage(data.message || 'Newsletter preference updated');
      setNewsletterStatus('success');
      await refreshProfile();
    } catch (error) {
      setNewsletterSubscribed(previousValue);
      setNewsletterMessage(error?.response?.data?.error || 'Unable to update newsletter preference');
      setNewsletterStatus('error');
    } finally {
      setNewsletterSaving(false);
    }
  };

  const addAddress = async (address) => {
    await api.post('/user/addresses', address);
    await loadAccountData();
  };

  const removeAddress = async (addressId) => {
    await api.delete(`/user/addresses/${addressId}`);
    await loadAccountData();
  };

  const editAddress = async (addressId, payload) => {
    const current = addresses.find((item) => item.id === addressId);
    if (!current) return;

    await api.delete(`/user/addresses/${addressId}`);
    await api.post('/user/addresses', {
      ...payload,
      country: payload.country || 'India',
      is_default: current.is_default
    });

    await loadAccountData();
  };

  const renderTab = () => {
    switch (activeTab) {
      case 'overview':
        return <AccountOverview stats={stats} recentOrders={orders.slice(0, 5)} onInvoice={downloadInvoice} isDark={isDark} />;
      case 'orders':
        return <OrdersPanel orders={orders} onInvoice={downloadInvoice} isDark={isDark} />;
      case 'profile':
        return <ProfileCard profile={profile} onSave={saveProfile} isDark={isDark} />;
      case 'coupons':
        return <CouponsPanel coupons={couponData} isDark={isDark} />;
      case 'addresses':
        return <AddressesPanel addresses={addresses} onAdd={addAddress} onEdit={editAddress} onRemove={removeAddress} isDark={isDark} />;
      case 'newsletter':
        return (
          <NewsletterPreferencesPanel
            subscribed={newsletterSubscribed}
            saving={newsletterSaving}
            message={newsletterMessage}
            status={newsletterStatus}
            onToggle={updateNewsletterPreference}
            isDark={isDark}
          />
        );
      case 'theme':
        return <ThemeSelector theme={theme} setTheme={setTheme} isDark={isDark} />;
      case 'delete-account':
        return (
          <DeleteAccountPanel
            onKeepAccount={() => setActiveTab('overview')}
            onDelete={async () => {
              await logout();
              navigate('/');
            }}
            isDark={isDark}
          />
        );
      case 'store-credit':
        return <PlaceholderPanel title="Store Credit" description="Track refunds and available store balance for your next purchase." isDark={isDark} />;
      case 'wallet':
        return <PlaceholderPanel title="Wallet" description="Manage wallet balance, credits, and linked payment instruments." isDark={isDark} />;
      case 'saved-cards':
        return <PlaceholderPanel title="Saved Cards" description="Securely manage your saved cards for one-click checkout." isDark={isDark} />;
      case 'saved-upi':
        return <PlaceholderPanel title="Saved UPI" description="Add or remove UPI IDs for instant and secure payments." isDark={isDark} />;
      case 'saved-wallets':
        return <PlaceholderPanel title="Saved Wallets / BNPL" description="Configure your preferred wallets and buy-now-pay-later providers." isDark={isDark} />;
      case 'terms':
        return <PlaceholderPanel title="Terms of Use" description="Read the terms governing use of HyperFit products and services." isDark={isDark} />;
      case 'privacy':
        return <PlaceholderPanel title="Privacy Policy" description="Understand how HyperFit collects, stores, and protects your data." isDark={isDark} />;
      default:
        return <AccountOverview stats={stats} recentOrders={orders.slice(0, 5)} onInvoice={downloadInvoice} isDark={isDark} />;
    }
  };

  if (!user) return <div className="hf-container page-gap">Login required.</div>;

  return (
    <div className="hf-container page-gap">
      <div className="mx-auto w-full space-y-4">
        <AccountHeader userName={profile.fullName || user.email} activeLabel={activeLabel} onOpenMenu={() => setMobileMenuOpen(true)} isDark={isDark} />

        <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
          <AccountSidebar
            groups={ACCOUNT_NAV_GROUPS}
            activeTab={activeTab}
            onSelect={setActiveTab}
            userName={profile.fullName || user.email}
            openMobile={mobileMenuOpen}
            onCloseMobile={() => setMobileMenuOpen(false)}
            isDark={isDark}
          />

          <main>
            {loading ? (
              <AccountSkeleton isDark={isDark} />
            ) : (
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeTab}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.2 }}
                >
                  {renderTab()}
                </motion.div>
              </AnimatePresence>
            )}
          </main>
        </div>
      </div>
    </div>
  );
}

export default Account;
