import { useEffect, useRef, useState } from 'react';

function Reveal({
  as = 'div',
  className = '',
  delay = 0,
  once = true,
  threshold = 0.18,
  children,
  ...rest
}) {
  const Tag = as;
  const nodeRef = useRef(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const node = nodeRef.current;
    if (!node) return undefined;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          if (once) observer.unobserve(node);
        } else if (!once) {
          setVisible(false);
        }
      },
      {
        threshold,
        rootMargin: '0px 0px -8% 0px'
      }
    );

    observer.observe(node);
    return () => observer.disconnect();
  }, [once, threshold]);

  return (
    <Tag
      ref={nodeRef}
      className={`reveal ${visible ? 'in' : ''} ${className}`.trim()}
      style={{ '--reveal-delay': `${delay}s` }}
      {...rest}
    >
      {children}
    </Tag>
  );
}

export default Reveal;
