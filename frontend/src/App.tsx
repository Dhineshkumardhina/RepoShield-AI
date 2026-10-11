import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { AppLayout } from './components/layout/AppLayout';

// Pages
import { LandingPage } from './pages/LandingPage';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { RepositoriesPage } from './pages/RepositoriesPage';
import { RepositoryDetailPage } from './pages/RepositoryDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { VerificationPage } from './pages/VerificationPage';
import { EvidencePage } from './pages/EvidencePage';
import { SettingsPage } from './pages/SettingsPage';
import { AiSecurityAnalyzerScreen } from './components/analyzer/AiSecurityAnalyzerScreen';

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        {/* Authenticated Workspace Routes wrapped in AppLayout */}
        <Route
          path="/dashboard"
          element={
            <AppLayout>
              <DashboardPage />
            </AppLayout>
          }
        />

        <Route
          path="/repositories"
          element={
            <AppLayout>
              <RepositoriesPage />
            </AppLayout>
          }
        />

        <Route
          path="/repositories/:id"
          element={
            <AppLayout>
              <RepositoryDetailPage />
            </AppLayout>
          }
        />

        <Route
          path="/findings"
          element={
            <AppLayout>
              <FindingsPage />
            </AppLayout>
          }
        />

        <Route
          path="/findings/:id"
          element={
            <AppLayout>
              <FindingDetailPage />
            </AppLayout>
          }
        />

        <Route
          path="/verification"
          element={
            <AppLayout>
              <VerificationPage />
            </AppLayout>
          }
        />

        <Route
          path="/evidence"
          element={
            <AppLayout>
              <EvidencePage />
            </AppLayout>
          }
        />

        <Route
          path="/settings"
          element={
            <AppLayout>
              <SettingsPage />
            </AppLayout>
          }
        />

        <Route
          path="/analyzer"
          element={
            <AppLayout>
              <AiSecurityAnalyzerScreen />
            </AppLayout>
          }
        />

        {/* Fallback to Dashboard */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AuthProvider>
  );
}
