import React, { createContext, useContext, useState, ReactNode } from 'react';

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
  id: 'usr-sarah-jenkins',
  email: 'sarah.jenkins@xerova.com',
  fullName: 'Dr. Sarah Jenkins',
  role: 'SecOps Lead',
  organization: 'Xerova Digital Solutions',
  isAuthenticated: true,
  sessionType: 'demo_operator',
};

interface AuthContextType {
  user: UserSession | null;
  login: (email: string, role?: UserSession['role']) => Promise<{ success: boolean; error?: string }>;
  register: (fullName: string, email: string, organization: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  // In-memory session strictly without writing credentials or tokens to localStorage
  const [user, setUser] = useState<UserSession | null>(DEFAULT_DEMO_USER);

  const login = async (email: string, role: UserSession['role'] = 'SecOps Lead') => {
    // Artificial latency simulating SSO negotiation
    await new Promise(resolve => setTimeout(resolve, 350));
    
    if (!email || !email.includes('@')) {
      return { success: false, error: 'Please provide a valid corporate email address.' };
    }

    const newUser: UserSession = {
      id: `usr-${Date.now()}`,
      email,
      fullName: email.split('@')[0].replace('.', ' ').replace(/\b\w/g, c => c.toUpperCase()),
      role,
      organization: 'Xerova Digital Solutions',
      isAuthenticated: true,
      sessionType: 'demo_operator',
    };

    setUser(newUser);
    return { success: true };
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
