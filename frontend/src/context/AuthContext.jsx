import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { authService } from '../services/authService';
import { bootstrapCsrf } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function init() {
      try {
        await bootstrapCsrf();
        const token = localStorage.getItem('hf_access_token');
        if (!token) {
          setLoading(false);
          return;
        }
        const { data } = await authService.me();
        setUser(data);
      } catch (_error) {
        localStorage.removeItem('hf_access_token');
      } finally {
        setLoading(false);
      }
    }
    init();
  }, []);

  const value = useMemo(
    () => ({
      user,
      loading,
      isAuthenticated: !!user,
      async login(payload) {
        const { data } = await authService.login(payload);
        localStorage.setItem('hf_access_token', data.access_token);
        const me = await authService.me();
        setUser(me.data);
        return data;
      },
      async register(payload) {
        const { data } = await authService.register(payload);
        localStorage.setItem('hf_access_token', data.access_token);
        const me = await authService.me();
        setUser(me.data);
        return data;
      },
      async logout() {
        await authService.logout();
        localStorage.removeItem('hf_access_token');
        setUser(null);
      },
      refreshProfile: async () => {
        const { data } = await authService.me();
        setUser(data);
      }
    }),
    [user, loading]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
