import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { NAV_LINKS } from '../utils/constants';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { useCart } from '../context/CartContext';

function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { summary } = useCart();
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname, location.search]);

  return (
    <header className="hf-navbar">
      <div className="hf-container navbar-inner">
        <Link className="brand" to="/">HyperFit</Link>

        <nav className="center-links" aria-label="Main navigation">
          {NAV_LINKS.map((item) => (
            <NavLink key={item.path} to={item.path}>{item.label}</NavLink>
          ))}
        </nav>

        <div className="right-actions">
          <Link className="text-link cart-chip" to="/cart">Cart <span>{summary.count}</span></Link>
          <button className="icon-btn" onClick={toggleTheme} aria-label="Toggle theme">{theme === 'light' ? 'Dark' : 'Light'}</button>
          {!user ? (
            <>
              <Link className="text-link hide-mobile" to="/login">Login</Link>
              <Link className="solid-link hide-mobile" to="/register">Register</Link>
            </>
          ) : (
            <>
              <button className="icon-btn hide-mobile" onClick={() => navigate('/account')}>Account</button>
              <button className="text-link hide-mobile" onClick={logout}>Logout</button>
            </>
          )}
          <button className="menu-toggle" onClick={() => setMobileOpen((value) => !value)} aria-label="Menu">☰</button>
        </div>
      </div>

      <div className={`mobile-nav ${mobileOpen ? 'open' : ''}`}>
        <nav>
          {NAV_LINKS.map((item) => (
            <NavLink key={item.path} to={item.path}>{item.label}</NavLink>
          ))}
          {!user ? (
            <>
              <Link to="/login">Login</Link>
              <Link to="/register">Register</Link>
            </>
          ) : (
            <>
              <Link to="/account">Account</Link>
              <button onClick={logout}>Logout</button>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}

export default Navbar;
