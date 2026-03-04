function Footer() {
  return (
    <footer className="hf-footer">
      <div className="hf-container footer-grid">
        <div>
          <h4>HyperFit</h4>
          <p>Minimal performance wear for modern lifestyles. Precision silhouettes inspired by Nike and H&M simplicity.</p>
          <div className="newsletter-row">
            <input placeholder="Enter email for newsletter" />
            <button>Subscribe</button>
          </div>
        </div>

        <div>
          <h5>Pages</h5>
          <ul>
            <li>Home</li>
            <li>Shop</li>
            <li>Account</li>
            <li>Wishlist</li>
          </ul>
        </div>

        <div>
          <h5>Quick Links</h5>
          <ul>
            <li>Men</li>
            <li>Women</li>
            <li>New Arrivals</li>
            <li>On Sale</li>
          </ul>
        </div>

        <div>
          <h5>Policies</h5>
          <ul>
            <li>Shipping Policy</li>
            <li>Return Policy</li>
            <li>Privacy Policy</li>
            <li>Terms of Service</li>
          </ul>
          <div className="social-row">IG · FB · X</div>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
