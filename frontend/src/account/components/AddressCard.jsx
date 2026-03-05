import { useState } from 'react';
import { motion } from 'framer-motion';

function AddressCard({ address, onSave, onRemove, isDark }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(address);

  const updateField = (key, value) => {
    setDraft((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <motion.article whileHover={{ y: -3 }} className={`rounded-2xl border ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}>
      {!editing ? (
        <div className="p-4">
          <div className="flex items-center justify-between gap-2">
            <h4 className="m-0 text-base font-semibold">{address.name}</h4>
            {address.is_default ? <span className={`rounded-full px-2 py-1 text-xs font-semibold uppercase ${isDark ? 'bg-slate-700 text-slate-200' : 'bg-slate-100 text-slate-600'}`}>Default</span> : null}
          </div>
          <p className={`m-0 mt-2 text-sm leading-6 ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
            {address.line1}
            {address.line2 ? `, ${address.line2}` : ''}<br />
            {address.city}, {address.state} - {address.pincode}<br />
            {address.country}
          </p>
          <p className={`m-0 mt-2 text-sm ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>Phone: {address.phone}</p>

          <div className="mt-4 flex gap-2">
            <button
              type="button"
              onClick={() => setEditing(true)}
              className={`rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.08em] ${isDark ? 'border-slate-600 bg-slate-800 text-slate-200' : 'border-slate-300 bg-white text-slate-700'}`}
            >
              Edit
            </button>
            <button
              type="button"
              onClick={() => onRemove(address.id)}
              className="rounded-full border border-rose-300 px-4 py-2 text-xs font-semibold uppercase tracking-[0.08em] text-rose-500"
            >
              Remove
            </button>
          </div>
        </div>
      ) : (
        <div className="grid gap-3 p-4">
          <input value={draft.name || ''} onChange={(event) => updateField('name', event.target.value)} placeholder="Name" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
          <input value={draft.line1 || ''} onChange={(event) => updateField('line1', event.target.value)} placeholder="Address line 1" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
          <input value={draft.line2 || ''} onChange={(event) => updateField('line2', event.target.value)} placeholder="Address line 2" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
          <div className="grid gap-3 sm:grid-cols-2">
            <input value={draft.city || ''} onChange={(event) => updateField('city', event.target.value)} placeholder="City" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
            <input value={draft.state || ''} onChange={(event) => updateField('state', event.target.value)} placeholder="State" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
            <input value={draft.pincode || ''} onChange={(event) => updateField('pincode', event.target.value)} placeholder="Pincode" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
            <input value={draft.phone || ''} onChange={(event) => updateField('phone', event.target.value)} placeholder="Phone" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={async () => { await onSave(address.id, draft); setEditing(false); }} className="rounded-full bg-rose-500 px-4 py-2 text-xs font-semibold uppercase tracking-[0.08em] text-white">Save</button>
            <button type="button" onClick={() => { setDraft(address); setEditing(false); }} className={`rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.08em] ${isDark ? 'border-slate-600 bg-slate-800 text-slate-200' : 'border-slate-300 bg-white text-slate-700'}`}>Cancel</button>
          </div>
        </div>
      )}
    </motion.article>
  );
}

export default AddressCard;
