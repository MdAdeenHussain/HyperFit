import { Suspense, lazy } from 'react';
import { Navigate, Outlet, Route, Routes } from 'react-router-dom';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Home from './pages/Home';
import Shop from './pages/Shop';
import ProductDetail from './pages/ProductDetail';
import Cart from './pages/Cart';
import Checkout from './pages/Checkout';
import Login from './pages/Login';
import AdminLogin from './pages/AdminLogin';
import Register from './pages/Register';
import Account from './pages/Account';
import Wishlist from './pages/Wishlist';
import AdminShell from './admin/layout/AdminShell';
import { useAuth } from './context/AuthContext';

const Dashboard = lazy(() => import('./admin/Dashboard'));
const Products = lazy(() => import('./admin/Products'));
const Orders = lazy(() => import('./admin/Orders'));
const Customers = lazy(() => import('./admin/Customers'));
const Coupons = lazy(() => import('./admin/Coupons'));
const Inventory = lazy(() => import('./admin/Inventory'));
const CMS = lazy(() => import('./admin/CMS'));
const EmailCampaigns = lazy(() => import('./admin/EmailCampaigns'));
const Reports = lazy(() => import('./admin/Reports'));
const Integrations = lazy(() => import('./admin/Integrations'));
const Settings = lazy(() => import('./admin/Settings'));

function BaseLayout() {
  return (
    <>
      <Navbar />
      <main className="hf-main"><Outlet /></main>
      <Footer />
    </>
  );
}

function Protected({ children }) {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return <div className="hf-container page-gap">Loading...</div>;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return children;
}

function AdminOnly({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="hf-container page-gap">Loading...</div>;
  if (!user || !user.is_admin) return <Navigate to="/admin/login" replace />;
  return children;
}

function AdminPageLoader() {
  return (
    <div className="admin-loader-screen">
      <div />
      <p>Loading admin module...</p>
    </div>
  );
}

function App() {
  return (
    <Routes>
      <Route element={<BaseLayout />}>
        <Route path="/" element={<Home />} />
        <Route path="/shop" element={<Shop />} />
        <Route path="/product/:slug" element={<ProductDetail />} />
        <Route path="/cart" element={<Cart />} />
        <Route path="/checkout" element={<Protected><Checkout /></Protected>} />
        <Route path="/login" element={<Login />} />
        <Route path="/admin/login" element={<AdminLogin />} />
        <Route path="/register" element={<Register />} />
        <Route path="/account" element={<Protected><Account /></Protected>} />
        <Route path="/wishlist" element={<Protected><Wishlist /></Protected>} />
      </Route>

      <Route path="/admin" element={<AdminOnly><AdminShell /></AdminOnly>}>
        <Route index element={<Suspense fallback={<AdminPageLoader />}><Dashboard /></Suspense>} />
        <Route path="products" element={<Suspense fallback={<AdminPageLoader />}><Products /></Suspense>} />
        <Route path="orders" element={<Suspense fallback={<AdminPageLoader />}><Orders /></Suspense>} />
        <Route path="customers" element={<Suspense fallback={<AdminPageLoader />}><Customers /></Suspense>} />
        <Route path="coupons" element={<Suspense fallback={<AdminPageLoader />}><Coupons /></Suspense>} />
        <Route path="inventory" element={<Suspense fallback={<AdminPageLoader />}><Inventory /></Suspense>} />
        <Route path="cms" element={<Suspense fallback={<AdminPageLoader />}><CMS /></Suspense>} />
        <Route path="email-campaigns" element={<Suspense fallback={<AdminPageLoader />}><EmailCampaigns /></Suspense>} />
        <Route path="reports" element={<Suspense fallback={<AdminPageLoader />}><Reports /></Suspense>} />
        <Route path="integrations" element={<Suspense fallback={<AdminPageLoader />}><Integrations /></Suspense>} />
        <Route path="settings" element={<Suspense fallback={<AdminPageLoader />}><Settings /></Suspense>} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
