import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';

const PROFILE_FIELDS = [
  { key: 'fullName', label: 'Full Name' },
  { key: 'mobile', label: 'Mobile Number' },
  { key: 'email', label: 'Email ID' },
  { key: 'gender', label: 'Gender' },
  { key: 'dateOfBirth', label: 'Date of Birth' },
  { key: 'location', label: 'Location' },
  { key: 'alternateMobile', label: 'Alternate Mobile' },
  { key: 'hintName', label: 'Hint Name' }
];

function ProfileCard({ profile, onSave, isDark }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(profile);

  const canSave = useMemo(() => draft.fullName?.trim() && draft.mobile?.trim(), [draft.fullName, draft.mobile]);

  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`rounded-2xl border p-4 sm:p-6 ${isDark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}
    >
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="m-0 text-xl font-semibold">Profile Details</h3>
          <p className={`m-0 mt-1 text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Manage your personal information.</p>
        </div>
      </div>

      <div className={`mt-5 grid gap-x-8 gap-y-4 ${editing ? 'sm:grid-cols-2' : 'sm:grid-cols-2'}`}>
        {PROFILE_FIELDS.map((item) => {
          const value = draft[item.key] || '- not added -';
          const editable = ['fullName', 'mobile', 'gender', 'dateOfBirth', 'location', 'alternateMobile', 'hintName'].includes(item.key);

          if (editing && editable) {
            return (
              <label key={item.key} className="block">
                <span className={`mb-2 block text-xs uppercase tracking-[0.12em] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{item.label}</span>
                <input
                  value={draft[item.key] || ''}
                  onChange={(event) => setDraft((prev) => ({ ...prev, [item.key]: event.target.value }))}
                  className={`w-full rounded-xl border px-3 py-2 text-sm ${isDark ? 'border-slate-600 bg-slate-800 text-white' : 'border-slate-300 bg-white text-slate-900'}`}
                />
              </label>
            );
          }

          return (
            <article key={item.key}>
              <p className={`m-0 text-xs uppercase tracking-[0.12em] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{item.label}</p>
              <p className="m-0 mt-2 text-base">{value}</p>
            </article>
          );
        })}
      </div>

      <div className={`mt-6 flex flex-wrap gap-3 ${editing ? 'sticky bottom-0 pt-3 backdrop-blur' : ''}`}>
        {!editing ? (
          <button
            type="button"
            onClick={() => setEditing(true)}
            className="rounded-full bg-rose-500 px-5 py-2 text-sm font-semibold uppercase tracking-[0.1em] text-white transition hover:bg-rose-600"
          >
            Edit Profile
          </button>
        ) : (
          <>
            <button
              type="button"
              disabled={!canSave}
              onClick={async () => {
                await onSave(draft);
                setEditing(false);
              }}
              className="rounded-full bg-rose-500 px-5 py-2 text-sm font-semibold uppercase tracking-[0.1em] text-white transition hover:bg-rose-600 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Save
            </button>
            <button
              type="button"
              onClick={() => {
                setDraft(profile);
                setEditing(false);
              }}
              className={`rounded-full border px-5 py-2 text-sm font-semibold uppercase tracking-[0.1em] ${isDark ? 'border-slate-600 bg-slate-800 text-slate-100' : 'border-slate-300 bg-white text-slate-700'}`}
            >
              Cancel
            </button>
          </>
        )}
      </div>
    </motion.section>
  );
}

export default ProfileCard;
