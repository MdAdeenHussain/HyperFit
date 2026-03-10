import { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { NAV_LINKS } from '../utils/constants';
import { useAuth } from '../context/AuthContext';
import { useCart } from '../context/CartContext';

function SearchIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M10.5 4.75a5.75 5.75 0 1 0 0 11.5a5.75 5.75 0 0 0 0-11.5ZM3.25 10.5a7.25 7.25 0 1 1 12.39 5.13l4.49 4.48a.75.75 0 1 1-1.06 1.06l-4.48-4.49A7.25 7.25 0 0 1 3.25 10.5Z" fill="currentColor" />
    </svg>
  );
}

function HeartIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 20.55 4.9 13.8a4.86 4.86 0 0 1 6.87-6.88L12 7.14l.23-.22a4.86 4.86 0 1 1 6.87 6.88L12 20.55Zm-5.97-7.84L12 18.38l5.97-5.67a3.36 3.36 0 0 0-4.75-4.75L12 9.18l-1.22-1.22a3.36 3.36 0 0 0-4.75 4.75Z" fill="currentColor" />
    </svg>
  );
}

function BagIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M8.25 7.5V7a3.75 3.75 0 1 1 7.5 0v.5h1.5A1.75 1.75 0 0 1 19 9.25v9A2.75 2.75 0 0 1 16.25 21h-8.5A2.75 2.75 0 0 1 5 18.25v-9A1.75 1.75 0 0 1 6.75 7.5h1.5Zm1.5 0h4.5V7a2.25 2.25 0 1 0-4.5 0v.5Zm-3 1.5a.25.25 0 0 0-.25.25v9c0 .69.56 1.25 1.25 1.25h8.5c.69 0 1.25-.56 1.25-1.25v-9a.25.25 0 0 0-.25-.25h-1.5v1.25a.75.75 0 0 1-1.5 0V9h-4.5v1.25a.75.75 0 0 1-1.5 0V9h-1.5Z" fill="currentColor" />
    </svg>
  );
}

function UserIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 12.25A4.25 4.25 0 1 1 12 3.75a4.25 4.25 0 0 1 0 8.5Zm0-7A2.75 2.75 0 1 0 12 10.75a2.75 2.75 0 0 0 0-5.5ZM5.25 18A3.25 3.25 0 0 1 8.5 14.75h7A3.25 3.25 0 0 1 18.75 18v2a.75.75 0 0 1-1.5 0v-2a1.75 1.75 0 0 0-1.75-1.75h-7A1.75 1.75 0 0 0 6.75 18v2a.75.75 0 0 1-1.5 0v-2Z" fill="currentColor" />
    </svg>
  );
}

function MenuIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 6.75A.75.75 0 0 1 4.75 6h14.5a.75.75 0 0 1 0 1.5H4.75A.75.75 0 0 1 4 6.75Zm0 5.25a.75.75 0 0 1 .75-.75h14.5a.75.75 0 0 1 0 1.5H4.75A.75.75 0 0 1 4 12Zm0 5.25a.75.75 0 0 1 .75-.75h14.5a.75.75 0 0 1 0 1.5H4.75A.75.75 0 0 1 4 17.25Z" fill="currentColor" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M6.97 5.91a.75.75 0 0 1 1.06 0L12 9.88l3.97-3.97a.75.75 0 1 1 1.06 1.06L13.06 10.94l3.97 3.97a.75.75 0 1 1-1.06 1.06L12 12l-3.97 3.97a.75.75 0 1 1-1.06-1.06l3.97-3.97-3.97-3.97a.75.75 0 0 1 0-1.06Z" fill="currentColor" />
    </svg>
  );
}

function ChevronIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M7.97 9.47a.75.75 0 0 1 1.06 0L12 12.44l2.97-2.97a.75.75 0 0 1 1.06 1.06l-3.5 3.5a.75.75 0 0 1-1.06 0l-3.5-3.5a.75.75 0 0 1 0-1.06Z" fill="currentColor" />
    </svg>
  );
}

function isNavActive(path, location) {
  const target = new URL(path, 'https://hyperfit.local');
  if (location.pathname !== target.pathname) return false;

  const targetParams = new URLSearchParams(target.search);
  const currentParams = new URLSearchParams(location.search);
  return Array.from(targetParams.entries()).every(([key, value]) => currentParams.get(key) === value);
}

function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  const { summary } = useCart();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [accountOpen, setAccountOpen] = useState(false);
  const accountMenuRef = useRef(null);
  const searchInputRef = useRef(null);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const routeSearch = location.pathname === '/shop' ? params.get('search') || '' : '';

    setSearchQuery(routeSearch);
    setSearchOpen(Boolean(routeSearch));
    setMobileOpen(false);
    setAccountOpen(false);
  }, [location.pathname, location.search]);

  useEffect(() => {
    if (!searchOpen) return undefined;

    const timeoutId = window.setTimeout(() => {
      searchInputRef.current?.focus();
    }, 120);

    return () => window.clearTimeout(timeoutId);
  }, [searchOpen]);

  useEffect(() => {
    const handlePointerDown = (event) => {
      if (accountMenuRef.current && !accountMenuRef.current.contains(event.target)) {
        setAccountOpen(false);
      }
    };

    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        setAccountOpen(false);
        setSearchOpen(false);
      }
    };

    document.addEventListener('pointerdown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const submitSearch = (event) => {
    event.preventDefault();
    const trimmed = searchQuery.trim();

    if (!trimmed) {
      searchInputRef.current?.focus();
      return;
    }

    navigate(`/shop?search=${encodeURIComponent(trimmed)}`);
  };

  const clearSearch = () => {
    setSearchQuery('');

    if (location.pathname === '/shop') {
      navigate('/shop');
      return;
    }

    searchInputRef.current?.focus();
  };

  const handleLogout = async () => {
    setAccountOpen(false);
    setMobileOpen(false);
    await logout();
    navigate('/');
  };

  return (
    <header className="hf-navbar">
      <div className="hf-container navbar-inner">
        <div className="navbar-left">
          <Link className="brand" to="/" aria-label="HyperFit home">
            {/* BRAND LOGO START */}
            {/* Insert logo here */}
            <span className="brand-mark" aria-hidden="true">HF</span>
            {/* BRAND LOGO END */}

            <span className="brand-copy">
              <strong>HyperFit</strong>
              <small>Motion wear</small>
            </span>
          </Link>
        </div>

        {/* MAIN NAVIGATION LINKS */}
        <nav className="center-links" aria-label="Main navigation">
          {NAV_LINKS.map((item) => (
            <Link key={item.path} to={item.path} className={isNavActive(item.path, location) ? 'active' : ''}>
              <span>{item.label}</span>
            </Link>
          ))}
        </nav>

        <div className="right-actions">
          <button
            type="button"
            className={`hf-nav-icon hf-search-toggle ${searchOpen ? 'active' : ''}`}
            onClick={() => setSearchOpen((value) => !value)}
            aria-label="Toggle search"
            aria-expanded={searchOpen}
            aria-controls="hf-nav-search-strip"
          >
            <SearchIcon />
          </button>

          <Link className="hf-nav-icon" to="/wishlist" aria-label="Go to wishlist">
            <HeartIcon />
          </Link>

          <Link className="hf-nav-icon hf-cart-action" to="/cart" aria-label={`Go to cart with ${summary.count} items`}>
            <BagIcon />
            {/* CART BADGE */}
            <span className="nav-count-badge" aria-hidden="true">{summary.count}</span>
          </Link>

          {/* ACCOUNT DROPDOWN */}
          <div className={`hf-account-shell ${accountOpen ? 'open' : ''}`} ref={accountMenuRef}>
            {!user ? (
              <Link className="hf-account-trigger" to="/login" aria-label="Login or sign in">
                <UserIcon />
                <span className="action-text">Login / Sign In</span>
              </Link>
            ) : (
              <>
                <button
                  type="button"
                  className="hf-account-trigger"
                  onClick={() => setAccountOpen((value) => !value)}
                  aria-label="Open account menu"
                  aria-expanded={accountOpen}
                  aria-controls="hf-account-dropdown"
                >
                  <UserIcon />
                  <span className="action-text">Account</span>
                  <span className="account-chevron" aria-hidden="true"><ChevronIcon /></span>
                </button>

                <div id="hf-account-dropdown" className="hf-account-dropdown" role="menu" aria-label="Account options">
                  <Link to="/account?tab=profile" role="menuitem" onClick={() => setAccountOpen(false)}>Profile</Link>
                  <Link to="/account?tab=orders" role="menuitem" onClick={() => setAccountOpen(false)}>Orders</Link>
                  <Link to="/account?tab=theme" role="menuitem" onClick={() => setAccountOpen(false)}>Settings</Link>
                  <button type="button" role="menuitem" onClick={handleLogout}>Logout</button>
                </div>
              </>
            )}
          </div>

          <button
            type="button"
            className="hf-nav-icon hf-menu-toggle"
            onClick={() => setMobileOpen((value) => !value)}
            aria-label="Toggle navigation menu"
            aria-expanded={mobileOpen}
            aria-controls="hf-mobile-nav"
          >
            {mobileOpen ? <CloseIcon /> : <MenuIcon />}
          </button>
        </div>
      </div>

      <div id="hf-nav-search-strip" className={`hf-search-strip ${searchOpen ? 'open' : ''}`}>
        <div className="hf-container hf-search-strip-inner">
          {/* SEARCH SYSTEM */}
          <form className="hf-search-form" role="search" onSubmit={submitSearch}>
            <label className="sr-only" htmlFor="hf-nav-search">Search for products</label>
            <span className="hf-search-leading" aria-hidden="true">
              <SearchIcon />
            </span>
            <input
              id="hf-nav-search"
              ref={searchInputRef}
              type="search"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search for products, brands and more"
            />
            {searchQuery ? (
              <button type="button" className="hf-search-clear" onClick={clearSearch} aria-label="Clear search">
                Clear
              </button>
            ) : null}
            <button type="submit" className="hf-search-submit" aria-label="Submit search">
              Search
            </button>
          </form>
        </div>
      </div>

      <div id="hf-mobile-nav" className={`mobile-nav ${mobileOpen ? 'open' : ''}`}>
        <div className="hf-container mobile-nav-inner">
          <nav aria-label="Mobile navigation">
            {NAV_LINKS.map((item) => (
              <Link key={item.path} to={item.path} className={isNavActive(item.path, location) ? 'active' : ''}>
                <span>{item.label}</span>
              </Link>
            ))}
          </nav>

          <div className="mobile-nav-actions">
            {!user ? (
              <Link className="mobile-account-link" to="/login">Login / Sign In</Link>
            ) : (
              <>
                <Link className="mobile-account-link" to="/account?tab=profile">Profile</Link>
                <Link className="mobile-account-link" to="/account?tab=orders">Orders</Link>
                <Link className="mobile-account-link" to="/account?tab=theme">Settings</Link>
                <button type="button" className="mobile-logout-btn" onClick={handleLogout}>Logout</button>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}

export default Navbar;
