import { motion } from 'framer-motion';

function LegalTemplate({ eyebrow, title, effectiveDate, sections = [] }) {
  return (
    <div className="hf-container page-gap">
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card-block">
        <p className="eyebrow">{eyebrow}</p>
        <h1 className="m-0 text-3xl">{title}</h1>
        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Effective Date: {effectiveDate}</p>
      </motion.section>

      <section className="grid gap-4">
        {sections.map((section, index) => (
          <motion.article
            key={section.heading}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.04 }}
            className="card-block"
          >
            <h2 className="m-0 text-xl">{section.heading}</h2>
            <p className="m-0 mt-2 text-sm text-slate-600 dark:text-slate-300">{section.body}</p>
          </motion.article>
        ))}
      </section>
    </div>
  );
}

export default LegalTemplate;
