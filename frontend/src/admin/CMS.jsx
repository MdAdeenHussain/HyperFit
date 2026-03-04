import { useState } from 'react';
import api from '../services/api';

function CMS() {
  const [hero, setHero] = useState({ title: 'Minimal Performance Wear', subtitle: 'New season now live', imageUrl: '' });
  const [campaign, setCampaign] = useState({ title: 'HyperFit Promo', content: 'Get 20% off on selected styles.' });

  return (
    <div className="admin-page">
      <h2>CMS</h2>

      <section className="card-block">
        <h3>Edit Hero Section</h3>
        <input placeholder="Title" value={hero.title} onChange={(e) => setHero((p) => ({ ...p, title: e.target.value }))} />
        <input placeholder="Subtitle" value={hero.subtitle} onChange={(e) => setHero((p) => ({ ...p, subtitle: e.target.value }))} />
        <input placeholder="Hero image URL" value={hero.imageUrl} onChange={(e) => setHero((p) => ({ ...p, imageUrl: e.target.value }))} />
        <button onClick={() => localStorage.setItem('hf_cms_hero', JSON.stringify(hero))}>Save Hero Content</button>
      </section>

      <section className="card-block">
        <h3>Admin Promotional Email</h3>
        <input placeholder="Campaign title" value={campaign.title} onChange={(e) => setCampaign((p) => ({ ...p, title: e.target.value }))} />
        <textarea placeholder="Campaign content" value={campaign.content} onChange={(e) => setCampaign((p) => ({ ...p, content: e.target.value }))} />
        <button onClick={async () => {
          const { data } = await api.post('/admin/campaigns/send', campaign);
          alert(`Sent to ${data.recipients} recipients`);
        }}>Send Campaign</button>
      </section>
    </div>
  );
}

export default CMS;
