import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { MEN_CATEGORIES, WOMEN_CATEGORIES } from '../utils/constants';
import Reveal from './Reveal';

function CategoryToggle() {
  const [active, setActive] = useState('men');

  const categories = useMemo(() => {
    const source = active === 'men' ? MEN_CATEGORIES : WOMEN_CATEGORIES;
    return source.map((name) => ({
      name,
      slug: name.toLowerCase().replace(/\s+/g, '-'),
      tone: active === 'men' ? 'tone-men' : 'tone-women'
    }));
  }, [active]);

  return (
    <Reveal as="section" className="category-toggle" threshold={0.15}>
      <div className="toggle-head">
        <h2>Shop By Category</h2>
        <div className="toggle-buttons" role="tablist" aria-label="Category switch">
          <button className={active === 'men' ? 'active' : ''} onClick={() => setActive('men')} role="tab" aria-selected={active === 'men'}>Men</button>
          <button className={active === 'women' ? 'active' : ''} onClick={() => setActive('women')} role="tab" aria-selected={active === 'women'}>Women</button>
        </div>
      </div>

      <div className={`subcat-grid ${active === 'men' ? 'slide-left' : 'slide-right'}`}>
        {categories.map((category, index) => (
          <article key={category.slug} className="subcat-card" style={{ '--reveal-delay': `${index * 0.04}s` }}>
            <div className={`subcat-image ${category.tone}`} />
            <h4>{category.name}</h4>
            <Link to={`/shop?category=${category.slug}`} className="text-link">Shop</Link>
          </article>
        ))}
      </div>
    </Reveal>
  );
}

export default CategoryToggle;
