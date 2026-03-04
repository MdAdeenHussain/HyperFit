import { useCallback, useEffect, useState } from 'react';

export default function useAdminFetch(fetcher, deps = [], immediate = true) {
  const [loading, setLoading] = useState(immediate);
  const [error, setError] = useState('');
  const [data, setData] = useState(null);

  const run = useCallback(async (...args) => {
    setLoading(true);
    setError('');
    try {
      const result = await fetcher(...args);
      setData(result);
      return result;
    } catch (err) {
      setError(err?.response?.data?.error || err?.message || 'Unable to load data');
      throw err;
    } finally {
      setLoading(false);
    }
  }, deps); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!immediate) return;
    run().catch(() => {});
  }, [run, immediate]);

  return { data, setData, loading, error, run };
}
