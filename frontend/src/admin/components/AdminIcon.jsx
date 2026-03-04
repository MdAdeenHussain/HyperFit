const iconProps = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round',
  strokeLinejoin: 'round'
};

function SvgWrap({ children }) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" {...iconProps}>
      {children}
    </svg>
  );
}

const ICONS = {
  dashboard: <SvgWrap><rect x="3" y="3" width="8" height="8" /><rect x="13" y="3" width="8" height="5" /><rect x="13" y="10" width="8" height="11" /><rect x="3" y="13" width="8" height="8" /></SvgWrap>,
  orders: <SvgWrap><path d="M3 7h18" /><path d="M6 3h12v18H6z" /><path d="M9 11h6" /><path d="M9 15h4" /></SvgWrap>,
  products: <SvgWrap><path d="M4 7l8-4 8 4-8 4-8-4z" /><path d="M4 7v10l8 4 8-4V7" /><path d="M12 11v10" /></SvgWrap>,
  customers: <SvgWrap><circle cx="9" cy="8" r="3" /><path d="M3 19c1.4-3 3.6-4.5 6-4.5s4.6 1.5 6 4.5" /><path d="M17 11a2.8 2.8 0 1 0 0-5.6" /></SvgWrap>,
  inventory: <SvgWrap><path d="M4 20V7l8-4 8 4v13" /><path d="M8 11h8" /><path d="M8 15h8" /></SvgWrap>,
  coupons: <SvgWrap><path d="M4 9a2 2 0 0 1 0-4h16v4" /><path d="M20 9v10H4V9" /><path d="M12 9v10" /></SvgWrap>,
  cms: <SvgWrap><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M8 8h8" /><path d="M8 12h6" /><path d="M8 16h4" /></SvgWrap>,
  email: <SvgWrap><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 7l9 6 9-6" /></SvgWrap>,
  reports: <SvgWrap><path d="M4 20V4" /><path d="M9 20V10" /><path d="M14 20V7" /><path d="M19 20V13" /></SvgWrap>,
  integrations: <SvgWrap><circle cx="8" cy="12" r="3" /><circle cx="16" cy="8" r="3" /><circle cx="16" cy="16" r="3" /><path d="M11 11l2-1" /><path d="M11 13l2 1" /></SvgWrap>,
  settings: <SvgWrap><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.8 1.8 0 0 0 .4 2l.1.1a2 2 0 0 1-2.8 2.8l-.1-.1a1.8 1.8 0 0 0-2-.4 1.8 1.8 0 0 0-1 1.6V21a2 2 0 0 1-4 0v-.2a1.8 1.8 0 0 0-1-1.6 1.8 1.8 0 0 0-2 .4l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.8 1.8 0 0 0 .4-2 1.8 1.8 0 0 0-1.6-1H3a2 2 0 1 1 0-4h.2a1.8 1.8 0 0 0 1.6-1 1.8 1.8 0 0 0-.4-2l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.8 1.8 0 0 0 2 .4H9a1.8 1.8 0 0 0 1-1.6V3a2 2 0 1 1 4 0v.2a1.8 1.8 0 0 0 1 1.6h.2a1.8 1.8 0 0 0 2-.4l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.8 1.8 0 0 0-.4 2V9a1.8 1.8 0 0 0 1.6 1H21a2 2 0 1 1 0 4h-.2a1.8 1.8 0 0 0-1.4 1z" /></SvgWrap>,
  menu: <SvgWrap><path d="M4 7h16" /><path d="M4 12h16" /><path d="M4 17h16" /></SvgWrap>,
  search: <SvgWrap><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.2-3.2" /></SvgWrap>,
  close: <SvgWrap><path d="M6 6l12 12" /><path d="M18 6l-12 12" /></SvgWrap>
  ,
  moon: <SvgWrap><path d="M21 13.5A8.5 8.5 0 1 1 10.5 3a7.2 7.2 0 0 0 10.5 10.5z" /></SvgWrap>,
  sun: <SvgWrap><circle cx="12" cy="12" r="4" /><path d="M12 2v2.2" /><path d="M12 19.8V22" /><path d="M4.9 4.9l1.6 1.6" /><path d="M17.5 17.5l1.6 1.6" /><path d="M2 12h2.2" /><path d="M19.8 12H22" /><path d="M4.9 19.1l1.6-1.6" /><path d="M17.5 6.5l1.6-1.6" /></SvgWrap>
};

function AdminIcon({ name }) {
  return ICONS[name] || ICONS.dashboard;
}

export default AdminIcon;
