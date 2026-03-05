import { useEffect } from 'react';
import { setMeta } from '../../utils/helpers';
import LegalTemplate from './LegalTemplate';

const sections = [
  {
    heading: 'Acceptance of Terms',
    body: 'By using HyperFit services and placing orders on our platform, you agree to comply with these terms and all applicable laws and regulations.'
  },
  {
    heading: 'Product Information',
    body: 'We strive for accurate descriptions and pricing. Minor visual variation may occur due to display settings and fabric batch differences.'
  },
  {
    heading: 'Orders and Payments',
    body: 'Orders are subject to confirmation, payment authorization, and stock availability. HyperFit may cancel or refund an order in exceptional situations.'
  },
  {
    heading: 'Account Responsibility',
    body: 'Users are responsible for maintaining account credentials and providing accurate profile and delivery details.'
  }
];

function TermsOfUse() {
  useEffect(() => {
    setMeta({ title: 'Terms of Use | HyperFit', description: 'Read HyperFit terms governing website usage, orders, and account responsibilities.' });
  }, []);

  return <LegalTemplate eyebrow="Legal" title="Terms of Use" effectiveDate="March 5, 2026" sections={sections} />;
}

export default TermsOfUse;
