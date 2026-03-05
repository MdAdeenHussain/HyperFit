import { useState } from 'react';
import { motion } from 'framer-motion';
import AddressCard from './AddressCard';

const EMPTY_ADDRESS = {
  name: '',
  line1: '',
  line2: '',
  city: '',
  state: '',
  country: 'India',
  pincode: '',
  phone: ''
};

function AddressesPanel({ addresses = [], onAdd, onEdit, onRemove, isDark }) {
  const [showNew, setShowNew] = useState(false);
  const [draft, setDraft] = useState(EMPTY_ADDRESS);

  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="m-0 text-xl font-semibold">Saved Addresses</h3>
          <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Manage delivery addresses for faster checkout.</p>
        </div>

        <button
          type="button"
          onClick={() => setShowNew((value) => !value)}
          className="rounded-full bg-indigo-600 px-5 py-2 text-sm font-semibold uppercase tracking-[0.08em] text-white transition hover:bg-indigo-700"
        >
          + Add New Address
        </button>
      </div>

      {showNew ? (
        <form
          className={`mt-4 grid gap-3 rounded-xl border p-4 ${isDark ? 'border-slate-700 bg-slate-800' : 'border-slate-200 bg-slate-50'}`}
          onSubmit={async (event) => {
            event.preventDefault();
            await onAdd(draft);
            setDraft(EMPTY_ADDRESS);
            setShowNew(false);
          }}
        >
          <input value={draft.name} onChange={(event) => setDraft((prev) => ({ ...prev, name: event.target.value }))} placeholder="Name" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-900 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
          <input value={draft.line1} onChange={(event) => setDraft((prev) => ({ ...prev, line1: event.target.value }))} placeholder="Address line 1" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-900 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
          <input value={draft.line2} onChange={(event) => setDraft((prev) => ({ ...prev, line2: event.target.value }))} placeholder="Address line 2" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-900 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
          <div className="grid gap-3 sm:grid-cols-2">
            <input value={draft.city} onChange={(event) => setDraft((prev) => ({ ...prev, city: event.target.value }))} placeholder="City" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-900 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
            <input value={draft.state} onChange={(event) => setDraft((prev) => ({ ...prev, state: event.target.value }))} placeholder="State" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-900 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
            <input value={draft.pincode} onChange={(event) => setDraft((prev) => ({ ...prev, pincode: event.target.value }))} placeholder="Pincode" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-900 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
            <input value={draft.phone} onChange={(event) => setDraft((prev) => ({ ...prev, phone: event.target.value }))} placeholder="Phone" className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-900 text-white' : 'border-slate-300 bg-white text-slate-900'}`} />
          </div>
          <div className="flex gap-2">
            <button type="submit" className="rounded-full bg-rose-500 px-4 py-2 text-xs font-semibold uppercase tracking-[0.08em] text-white">Save Address</button>
            <button type="button" onClick={() => { setShowNew(false); setDraft(EMPTY_ADDRESS); }} className={`rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.08em] ${isDark ? 'border-slate-600 bg-slate-900 text-slate-200' : 'border-slate-300 bg-white text-slate-700'}`}>Cancel</button>
          </div>
        </form>
      ) : null}

      <div className="mt-4 grid gap-3">
        {addresses.map((address) => (
          <AddressCard key={address.id} address={address} onSave={onEdit} onRemove={onRemove} isDark={isDark} />
        ))}
      </div>
    </motion.section>
  );
}

export default AddressesPanel;
