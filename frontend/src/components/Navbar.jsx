import { Link, NavLink, useNavigate } from 'react-router-dom';
import { NAV_LINKS } from '../utils/constants';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

function Navbar() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="hf-navbar">
      <div className="hf-container navbar-inner">
        <Link className="brand" to="/">HyperFit</Link>

        <nav className="center-links">
          {NAV_LINKS.map((item) => (
            <NavLink key={item.path} to={item.path}>{item.label}</NavLink>
          ))}
        </nav>

        <div className="right-actions">
          <button className="icon-btn" onClick={toggleTheme}>{theme === 'light' ? 'Dark' : 'Light'}</button>
          {!user ? (
            <>
              <Link className="text-link" to="/login">Login</Link>
              <Link className="solid-link" to="/register">Register</Link>
            </>
          ) : (
            <>
              <button className="icon-btn" onClick={() => navigate('/account')}>Account</button>
              <button className="text-link" onClick={logout}>Logout</button>
            </>
          )}
        </div>
      </div>
    </header>
  );
}

export default Navbar;
