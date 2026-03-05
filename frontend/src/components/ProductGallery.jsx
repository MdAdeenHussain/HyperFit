import { useMemo, useState } from 'react';

function ProductGallery({ images = [] }) {
  const safeImages = useMemo(() => (images.length ? images : ['/placeholder.png']), [images]);
  const [activeIndex, setActiveIndex] = useState(0);

  const next = () => {
    setActiveIndex((prev) => (prev + 1) % safeImages.length);
  };

  const previous = () => {
    setActiveIndex((prev) => (prev - 1 + safeImages.length) % safeImages.length);
  };

  return (
    <div className="gallery-layout">
      <div className="thumbs">
        {safeImages.map((img, index) => (
          <button key={img + index} className={activeIndex === index ? 'active' : ''} onClick={() => setActiveIndex(index)}>
            <img loading="lazy" src={img} alt={`Product ${index + 1}`} />
          </button>
        ))}
      </div>

      <div className="viewer">
        <img loading="lazy" src={safeImages[activeIndex]} alt="Selected product" className="main-image" />

        {activeIndex >= 1 && (
          <div className="feature-overlay overlay-slide">
            <div>
              <p>Breathable fabric blend</p>
              <p>Adaptive fit for movement</p>
              <p className="arrow-slide">Performance mapped zones</p>
            </div>
          </div>
        )}

        {safeImages.length > 1 && (
          <>
            <button className="gallery-arrow left" onClick={previous} aria-label="Previous image">‹</button>
            <button className="gallery-arrow right" onClick={next} aria-label="Next image">›</button>
          </>
        )}
      </div>
    </div>
  );
}

export default ProductGallery;
