import { useEffect } from 'react';
import { setMeta } from '../../utils/helpers';
import LegalTemplate from './LegalTemplate';

const sections = [
  {
    heading: 'What Are Cookies',
    body: 'Cookies are small files used to remember preferences, session state, and analytics signals for better website experience.'
  },
  {
    heading: 'How HyperFit Uses Cookies',
    body: 'We use cookies for login continuity, cart persistence, theme preferences, traffic insights, and basic performance optimization.'
  },
  {
    heading: 'Third-Party Cookies',
    body: 'Some integrations may set cookies for secure payments, analytics, or embedded media. These are governed by their providers policies.'
  },
  {
    heading: 'Managing Cookies',
    body: 'You can control or delete cookies in your browser settings. Disabling some cookies may affect site features and checkout flow.'
  }
];

function CookiePolicy() {
  useEffect(() => {
    setMeta({ title: 'Cookie Policy | HyperFit', description: 'Review how HyperFit uses cookies and how you can manage cookie preferences.' });
  }, []);

  return <LegalTemplate eyebrow="Legal" title="Cookie Policy" effectiveDate="March 5, 2026" sections={sections} />;
}

export default CookiePolicy;
