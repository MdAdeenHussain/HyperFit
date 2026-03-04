import { useMemo, useState } from 'react';
import { MEN_CATEGORIES, WOMEN_CATEGORIES } from '../utils/constants';

function CategoryToggle() {
  const [active, setActive] = useState('men');
  const categories = useMemo(() => (active === 'men' ? MEN_CATEGORIES : WOMEN_CATEGORIES), [active]);

  return (
    <section className="category-toggle">
      <div className="toggle-head">
        <h2>Shop By Category</h2>
        <div className="toggle-buttons">
          <button className={active === 'men' ? 'active' : ''} onClick={() => setActive('men')}>Men</button>
          <button className={active === 'women' ? 'active' : ''} onClick={() => setActive('women')}>Women</button>
        </div>
      </div>

      <div className="subcat-grid">
        {categories.map((category) => (
          <article key={category} className="subcat-card">
            <div className="subcat-image" />
            <h4>{category}</h4>
          </article>
        ))}
      </div>
    </section>
  );
}

export default CategoryToggle;
