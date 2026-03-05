import { useEffect } from 'react';
import { setMeta } from '../../utils/helpers';
import LegalTemplate from './LegalTemplate';

const sections = [
  {
    heading: 'Data We Collect',
    body: 'HyperFit collects account details, order information, shipping addresses, and interaction events required for commerce and service quality.'
  },
  {
    heading: 'How We Use Data',
    body: 'Your data is used to process orders, provide customer support, send transactional communications, and improve website functionality.'
  },
  {
    heading: 'Data Sharing',
    body: 'We share required information with trusted partners like payment gateways and shipping providers only to complete transactions and deliveries.'
  },
  {
    heading: 'Security and Retention',
    body: 'HyperFit applies technical and operational safeguards to protect data. Information is retained based on legal, accounting, and service requirements.'
  }
];

function PrivacyPolicy() {
  useEffect(() => {
    setMeta({ title: 'Privacy Policy | HyperFit', description: 'Learn how HyperFit collects, uses, secures, and manages your personal information.' });
  }, []);

  return <LegalTemplate eyebrow="Legal" title="Privacy Policy" effectiveDate="March 5, 2026" sections={sections} />;
}

export default PrivacyPolicy;
