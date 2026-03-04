import { useMemo, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import AdminIcon from '../components/AdminIcon';
import { ADMIN_NAV_ITEMS } from './adminNav';
import { useAuth } from '../../context/AuthContext';

function Sidebar({ closeDrawer }) {
  const location = useLocation();

  const activeTitle = useMemo(() => {
    const match = ADMIN_NAV_ITEMS.find((item) => location.pathname === item.path || (item.path !== '/admin' && location.pathname.startsWith(item.path)));
    return match?.label || 'Dashboard';
  }, [location.pathname]);

  return (
    <aside className="admin-panel-sidebar">
      <div className="admin-brand-row">
        <div className="admin-brand-mark">HF</div>
        <div>
          <strong>HyperFit</strong>
          <p>Commerce Admin</p>
        </div>
      </div>

      <nav className="admin-nav-list" aria-label="Admin navigation">
        {ADMIN_NAV_ITEMS.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            onClick={closeDrawer}
            className={({ isActive }) => {
              const isMatch = isActive || (item.path !== '/admin' && location.pathname.startsWith(item.path));
              return isMatch ? 'active' : '';
            }}
          >
            <AdminIcon name={item.icon} />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="admin-sidebar-footer">
        <small>Current section</small>
        <strong>{activeTitle}</strong>
      </div>
    </aside>
  );
}

function AdminShell() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('hf_admin_theme') || 'light');

  const toggleTheme = () => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      localStorage.setItem('hf_admin_theme', next);
      return next;
    });
  };

  return (
    <div className={`admin-app-shell ${theme === 'dark' ? 'admin-dark' : 'admin-light'}`}>
      <div className="admin-desktop-sidebar">
        <Sidebar />
      </div>

      <div className={drawerOpen ? 'admin-mobile-drawer open' : 'admin-mobile-drawer'}>
        <div className="drawer-backdrop" onClick={() => setDrawerOpen(false)} role="button" tabIndex={0} onKeyDown={() => setDrawerOpen(false)} />
        <div className="drawer-panel">
          <Sidebar closeDrawer={() => setDrawerOpen(false)} />
        </div>
      </div>

      <main className="admin-main-stage">
        <header className="admin-topbar">
          <button className="topbar-icon-btn only-mobile" onClick={() => setDrawerOpen(true)} aria-label="Open menu">
            <AdminIcon name="menu" />
          </button>

          <div className="topbar-search">
            <AdminIcon name="search" />
            <input type="search" placeholder="Search orders, products, customers" />
          </div>

          <div className="topbar-actions">
            <div className="admin-user-chip">
              <span>{user?.first_name?.[0] || 'A'}</span>
              <div>
                <strong>{user?.first_name || 'Admin'} {user?.last_name || ''}</strong>
                <small>Administrator</small>
              </div>
            </div>
            <button className="topbar-icon-btn" onClick={toggleTheme} aria-label="Toggle dark mode">
              <AdminIcon name={theme === 'dark' ? 'sun' : 'moon'} />
              <span className="topbar-theme-label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
            </button>
            <button
              className="topbar-icon-btn"
              onClick={async () => {
                await logout();
                navigate('/admin/login');
              }}
            >
              Logout
            </button>
          </div>
        </header>

        <section className="admin-page-stage">
          <Outlet />
        </section>
      </main>
    </div>
  );
}

export default AdminShell;
