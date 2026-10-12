import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { loginWithCredentials, setAuthToken, getAuthToken } from '../services/api';

export interface UserSession {
  id: string;
  email: string;
  fullName: string;
  role: 'SecOps Lead' | 'Security Analyst' | 'Staff Engineer';
  organization: string;
  isAuthenticated: boolean;
  sessionType: 'demo_operator';
}

const DEFAULT_DEMO_USER: UserSession = {
  id: 'usr-dev-seed-001',
  email: 'dev@xerova.com',
  fullName: 'Xerova Security Lead',
  role: 'SecOps Lead',
  organization: 'Xerova Digital Solutions',
  isAuthenticated: true,
  sessionType: 'demo_operator',
};

interface AuthContextType {
  user: UserSession | null;
  login: (email: string, password?: string, role?: UserSession['role']) => Promise<{ success: boolean; error?: string }>;
  register: (fullName: string, email: string, organization: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserSession | null>(DEFAULT_DEMO_USER);

  // Automatically authenticate with local dev seed account on initial mount if not yet authenticated
  useEffect(() => {
    const initAuth = async () => {
      const existingToken = getAuthToken();
      if (!existingToken) {
        try {
          const res = await loginWithCredentials('dev@xerova.com', 'XerovaDevPass2026!');
          if (res?.access_token) {
            setUser({
              id: res.user.id,
              email: res.user.email,
              fullName: 'Xerova Security Lead',
              role: 'SecOps Lead',
              organization: 'Xerova Digital Solutions',
              isAuthenticated: true,
              sessionType: 'demo_operator',
            });
          }
        } catch {
          // Non-blocking in test or disconnected offline modes
        }
      }
    };
    initAuth();
  }, []);

  const login = async (
    email: string,
    password: string = 'XerovaDevPass2026!',
    role: UserSession['role'] = 'SecOps Lead'
  ) => {
    try {
      const res = await loginWithCredentials(email, password);
      if (res?.access_token) {
        const newUser: UserSession = {
          id: res.user.id,
          email: res.user.email,
          fullName: email.split('@')[0].replace('.', ' ').replace(/\b\w/g, c => c.toUpperCase()),
          role,
          organization: 'Xerova Digital Solutions',
          isAuthenticated: true,
          sessionType: 'demo_operator',
        };
        setUser(newUser);
        return { success: true };
      }
      return { success: false, error: 'Authentication failed.' };
    } catch (err: any) {
      return { success: false, error: err.message || 'Authentication failed.' };
    }
  };

  const register = async (fullName: string, email: string, organization: string) => {
    await new Promise(resolve => setTimeout(resolve, 400));
    
    if (!email || !fullName || !organization) {
      return { success: false, error: 'All fields are required for enterprise registration.' };
    }

    const newUser: UserSession = {
      id: `usr-${Date.now()}`,
      email,
      fullName,
      role: 'Security Analyst',
      organization,
      isAuthenticated: true,
      sessionType: 'demo_operator',
    };

    setUser(newUser);
    return { success: true };
  };

  const logout = () => {
    setAuthToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
