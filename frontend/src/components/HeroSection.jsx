import { Link } from 'react-router-dom';
import Reveal from './Reveal';

function HeroSection({ heroImage }) {
  return (
    <section className="hero-section hero-premium">
      <div className="hero-noise" aria-hidden="true" />
      <div className="hero-float-shape hero-float-shape-a" aria-hidden="true" />
      <div className="hero-float-shape hero-float-shape-b" aria-hidden="true" />

      <Reveal className="hero-copy" threshold={0.1}>
        <p className="eyebrow">HyperFit Collection</p>
        <h1>Engineered for Performance</h1>
        <p className="hero-subtext">Premium training wear designed for athletes.</p>
        <div className="hero-actions">
          <Link className="solid-link" to="/shop?category=men">Shop Men</Link>
          <Link className="ghost-link" to="/shop?category=women">Shop Women</Link>
        </div>
      </Reveal>

      <Reveal className="hero-media" delay={0.12} threshold={0.1}>
        <img loading="lazy" src={heroImage || '/placeholder.png'} alt="HyperFit athlete wear" />
      </Reveal>
    </section>
  );
}

export default HeroSection;
