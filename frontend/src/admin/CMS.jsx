import { useEffect, useMemo, useState } from 'react';
import adminService from '../services/adminService';
import AdminSkeleton from './components/AdminSkeleton';

function clone(obj) {
  return JSON.parse(JSON.stringify(obj || {}));
}

function CMS() {
  const [pages, setPages] = useState([]);
  const [selectedPage, setSelectedPage] = useState('home');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const [draftContent, setDraftContent] = useState({});
  const [liveContent, setLiveContent] = useState({});
  const [previewContent, setPreviewContent] = useState(null);
  const [changeSummary, setChangeSummary] = useState(null);
  const [versions, setVersions] = useState([]);

  const hero = useMemo(() => draftContent.hero || {}, [draftContent]);
  const footer = useMemo(() => draftContent.footer_content || {}, [draftContent]);
  const seo = useMemo(() => draftContent.seo_metadata || {}, [draftContent]);

  const loadPages = async () => {
    const { data } = await adminService.getCmsPages();
    setPages(data.items || []);
  };

  const loadPageDetail = async (pageKey) => {
    setLoading(true);
    setError('');
    try {
      const { data } = await adminService.getCmsPage(pageKey);
      setDraftContent(clone(data.page?.draft_content || {}));
      setLiveContent(clone(data.page?.live_content || {}));
      setPreviewContent(null);
      setVersions(data.versions || []);
      setChangeSummary(null);
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load CMS page');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPages().catch(() => {});
  }, []);

  useEffect(() => {
    loadPageDetail(selectedPage);
  }, [selectedPage]); // eslint-disable-line react-hooks/exhaustive-deps

  const updateDraftField = (path, value) => {
    setDraftContent((prev) => {
      const next = clone(prev);
      let current = next;
      for (let i = 0; i < path.length - 1; i += 1) {
        current[path[i]] = current[path[i]] || {};
        current = current[path[i]];
      }
      current[path[path.length - 1]] = value;
      return next;
    });
  };

  const saveDraft = async () => {
    setSaving(true);
    setError('');
    try {
      const { data } = await adminService.saveCmsDraft(selectedPage, draftContent);
      setChangeSummary(data.change_summary || null);
      const detail = await adminService.getCmsPage(selectedPage);
      setVersions(detail.data.versions || []);
      await loadPages();
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Failed to save draft');
    } finally {
      setSaving(false);
    }
  };

  const previewDraft = async () => {
    setSaving(true);
    setError('');
    try {
      const { data } = await adminService.previewCms(selectedPage, draftContent);
      setPreviewContent(data.preview_content || draftContent);
      setChangeSummary(data.change_summary || null);
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Failed to generate preview');
    } finally {
      setSaving(false);
    }
  };

  const publishDraft = async () => {
    setSaving(true);
    setError('');
    try {
      const { data } = await adminService.publishCms(selectedPage);
      setChangeSummary(data.change_summary || null);
      await loadPageDetail(selectedPage);
      await loadPages();
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Failed to publish changes');
    } finally {
      setSaving(false);
    }
  };

  const restoreVersion = async (versionId, publish = false) => {
    setSaving(true);
    try {
      await adminService.restoreCmsVersion(selectedPage, versionId, publish);
      await loadPageDetail(selectedPage);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="admin-page">
      <section className="page-head-row">
        <div>
          <h1>CMS / Website Editor</h1>
          <p>Edit homepage content in draft mode, review changes, preview, publish and rollback versions.</p>
        </div>
        <select value={selectedPage} onChange={(e) => setSelectedPage(e.target.value)}>
          {pages.map((page) => <option key={page.page_key} value={page.page_key}>{page.title}</option>)}
        </select>
      </section>

      {error ? <div className="admin-error">{error}</div> : null}
      {loading ? <AdminSkeleton rows={8} /> : null}

      {!loading ? (
        <section className="admin-cms-grid">
          <article className="admin-panel-card">
            <header>
              <h3>Visual Editor (Draft Mode)</h3>
              <span className="pill warning">Safe editing mode enabled</span>
            </header>

            <div className="admin-form-grid">
              <h4>Hero Section</h4>
              <input placeholder="Hero title" value={hero.title || ''} onChange={(e) => updateDraftField(['hero', 'title'], e.target.value)} />
              <input placeholder="Hero subtitle" value={hero.subtitle || ''} onChange={(e) => updateDraftField(['hero', 'subtitle'], e.target.value)} />
              <input placeholder="Hero CTA text" value={hero.cta_text || ''} onChange={(e) => updateDraftField(['hero', 'cta_text'], e.target.value)} />
              <input placeholder="Hero image URL" value={hero.image || ''} onChange={(e) => updateDraftField(['hero', 'image'], e.target.value)} />

              <h4>Footer Content</h4>
              <textarea placeholder="Footer about text" value={footer.about || ''} onChange={(e) => updateDraftField(['footer_content', 'about'], e.target.value)} />
              <input placeholder="Footer support email" value={footer.help_email || ''} onChange={(e) => updateDraftField(['footer_content', 'help_email'], e.target.value)} />

              <h4>SEO Metadata</h4>
              <input placeholder="SEO title" value={seo.title || ''} onChange={(e) => updateDraftField(['seo_metadata', 'title'], e.target.value)} />
              <textarea placeholder="SEO description" value={seo.description || ''} onChange={(e) => updateDraftField(['seo_metadata', 'description'], e.target.value)} />
            </div>

            <div className="form-btn-row sticky-footer-row">
              <button className="ghost" onClick={previewDraft} disabled={saving}>Preview</button>
              <button className="admin-btn" onClick={saveDraft} disabled={saving}>{saving ? 'Saving...' : 'Save Draft'}</button>
              <button className="admin-btn success" onClick={publishDraft} disabled={saving}>Publish</button>
            </div>

            {changeSummary ? (
              <section className="change-summary-panel">
                <h4>Change Review Summary</h4>
                <p>{changeSummary.change_count || 0} changes detected</p>
                <div className="summary-columns">
                  <div>
                    <strong>Changed Text</strong>
                    <ul>{(changeSummary.changed_text || []).slice(0, 5).map((entry) => <li key={entry}>{entry}</li>)}</ul>
                  </div>
                  <div>
                    <strong>Changed Image</strong>
                    <ul>{(changeSummary.changed_image || []).slice(0, 5).map((entry) => <li key={entry}>{entry}</li>)}</ul>
                  </div>
                  <div>
                    <strong>Changed Layout</strong>
                    <ul>{(changeSummary.changed_layout || []).slice(0, 5).map((entry) => <li key={entry}>{entry}</li>)}</ul>
                  </div>
                </div>
              </section>
            ) : null}
          </article>

          <article className="admin-panel-card">
            <header><h3>Live Preview Panel</h3></header>
            <div className="cms-preview">
              <div className="preview-hero" style={{ backgroundImage: `url(${(previewContent || draftContent).hero?.image || ''})` }}>
                <div>
                  <small>Hero Section</small>
                  <h2>{(previewContent || draftContent).hero?.title || 'Hero title'}</h2>
                  <p>{(previewContent || draftContent).hero?.subtitle || 'Hero subtitle'}</p>
                  <button>{(previewContent || draftContent).hero?.cta_text || 'CTA'}</button>
                </div>
              </div>

              <div className="preview-footer">
                <small>Footer</small>
                <p>{(previewContent || draftContent).footer_content?.about || ''}</p>
                <span>{(previewContent || draftContent).footer_content?.help_email || ''}</span>
              </div>

              <div className="preview-seo">
                <small>SEO</small>
                <strong>{(previewContent || draftContent).seo_metadata?.title || ''}</strong>
                <p>{(previewContent || draftContent).seo_metadata?.description || ''}</p>
              </div>
            </div>

            <section className="version-history">
              <header><h4>Version History</h4></header>
              <div className="version-list">
                {versions.map((version) => (
                  <div key={version.id} className="version-item">
                    <div>
                      <strong>v{version.version_number}</strong>
                      <p>{version.action.replace('_', ' ')}</p>
                      <small>{new Date(version.created_at).toLocaleString()}</small>
                    </div>
                    <div className="row-actions-inline">
                      <button className="ghost" onClick={() => restoreVersion(version.id, false)}>Restore Draft</button>
                      <button className="ghost" onClick={() => restoreVersion(version.id, true)}>Rollback Live</button>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <details>
              <summary>Raw JSON editor</summary>
              <textarea
                className="json-editor"
                value={JSON.stringify(draftContent, null, 2)}
                onChange={(e) => {
                  try {
                    setDraftContent(JSON.parse(e.target.value));
                    setError('');
                  } catch (_error) {
                    setError('Invalid JSON in raw editor');
                  }
                }}
              />
            </details>
          </article>
        </section>
      ) : null}

      <section className="admin-table-card">
        <header><h3>All CMS Pages</h3></header>
        <div className="admin-table-scroll">
          <table className="admin-table compact">
            <thead>
              <tr><th>Page</th><th>Published</th><th>Updated</th><th>Published At</th></tr>
            </thead>
            <tbody>
              {pages.map((page) => (
                <tr key={page.page_key}>
                  <td>{page.title}</td>
                  <td><span className={page.is_published ? 'pill success' : 'pill warning'}>{page.is_published ? 'Published' : 'Draft'}</span></td>
                  <td>{new Date(page.updated_at).toLocaleString()}</td>
                  <td>{page.published_at ? new Date(page.published_at).toLocaleString() : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default CMS;
