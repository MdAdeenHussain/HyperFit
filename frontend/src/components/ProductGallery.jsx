import { useMemo, useRef, useState } from 'react';

function ProductGallery({ images = [] }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const [showOverlay, setShowOverlay] = useState(false);
  const scrollerRef = useRef(null);

  const safeImages = useMemo(() => (images.length ? images : ['/placeholder.png']), [images]);

  const onScroll = () => {
    const element = scrollerRef.current;
    if (!element) return;
    const imageHeight = element.clientHeight;
    const index = Math.round(element.scrollTop / Math.max(imageHeight, 1));
    setActiveIndex(Math.min(index, safeImages.length - 1));
    setShowOverlay(index >= 1);
  };

  return (
    <div className="gallery-layout">
      <div className="thumbs">
        {safeImages.map((img, i) => (
          <button key={img + i} className={activeIndex === i ? 'active' : ''} onClick={() => setActiveIndex(i)}>
            <img loading="lazy" src={img} alt={`Product ${i + 1}`} />
          </button>
        ))}
      </div>

      <div className="viewer" ref={scrollerRef} onScroll={onScroll}>
        <img loading="lazy" src={safeImages[activeIndex]} alt="Selected product" className="main-image" />
        {showOverlay && (
          <div className="feature-overlay">
            <div>
              <p>Breathable fabric blend</p>
              <p>Adaptive fit for movement</p>
              <p className="arrow-slide">→</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default ProductGallery;
