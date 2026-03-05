import { useEffect } from 'react';
import { setMeta } from '../../utils/helpers';
import LegalTemplate from './LegalTemplate';

const sections = [
  {
    heading: 'Return Window',
    body: 'Most HyperFit items are eligible for return or exchange within 30 days from delivery, subject to item condition and packaging checks.'
  },
  {
    heading: 'Refund Method',
    body: 'Refunds are initiated to the original payment method or eligible store credit wallet after quality verification of returned products.'
  },
  {
    heading: 'Non-Returnable Items',
    body: 'Items marked final sale, used products, or products without original tags may not qualify for return and refund.'
  },
  {
    heading: 'Processing Time',
    body: 'Approved refunds are typically processed within 5-10 business days depending on payment provider timelines.'
  }
];

function RefundPolicy() {
  useEffect(() => {
    setMeta({ title: 'Refund Policy | HyperFit', description: 'Understand HyperFit return eligibility, exchange rules, and refund processing timelines.' });
  }, []);

  return <LegalTemplate eyebrow="Legal" title="Refund Policy" effectiveDate="March 5, 2026" sections={sections} />;
}

export default RefundPolicy;
