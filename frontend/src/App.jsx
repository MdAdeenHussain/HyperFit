import { Link, Navigate, Outlet, Route, Routes } from 'react-router-dom';
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
import Dashboard from './admin/Dashboard';
import Products from './admin/Products';
import Orders from './admin/Orders';
import Customers from './admin/Customers';
import Coupons from './admin/Coupons';
import Inventory from './admin/Inventory';
import CMS from './admin/CMS';
import { useAuth } from './context/AuthContext';

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

function AdminLayout() {
  return (
    <div className="admin-shell">
      <aside className="admin-sidebar">
        <h3>Admin</h3>
        <Link to="/admin">Dashboard</Link>
        <Link to="/admin/products">Products</Link>
        <Link to="/admin/orders">Orders</Link>
        <Link to="/admin/customers">Customers</Link>
        <Link to="/admin/coupons">Coupons</Link>
        <Link to="/admin/inventory">Inventory</Link>
        <Link to="/admin/cms">CMS</Link>
      </aside>
      <section className="admin-content"><Outlet /></section>
    </div>
  );
}

function AdminOnly({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="hf-container page-gap">Loading...</div>;
  if (!user || !user.is_admin) return <Navigate to="/admin/login" replace />;
  return children;
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

      <Route path="/admin" element={<AdminOnly><AdminLayout /></AdminOnly>}>
        <Route index element={<Dashboard />} />
        <Route path="products" element={<Products />} />
        <Route path="orders" element={<Orders />} />
        <Route path="customers" element={<Customers />} />
        <Route path="coupons" element={<Coupons />} />
        <Route path="inventory" element={<Inventory />} />
        <Route path="cms" element={<CMS />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
