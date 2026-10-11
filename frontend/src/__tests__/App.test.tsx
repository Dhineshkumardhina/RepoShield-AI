import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../App';

describe('RepoShield AI Frontend Routes & Components', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url.includes('/api/v1/health')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            status: 'ok',
            service: 'RepoShield AI',
            version: '0.1.0',
            environment: 'development',
            database: { status: 'connected', dialect: 'sqlite' },
            uptime_seconds: 12.3,
          }),
        });
      }

      if (url.includes('/api/v1/repositories')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            {
              id: 'repo-auth-gateway',
              name: 'xerova/auth-gateway',
              default_branch: 'main',
              health_score: 84,
              critical_count: 1,
              high_count: 2,
              medium_count: 4,
              low_count: 0,
              is_active: true,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
          ]),
        });
      }

      if (url.includes('/api/v1/findings')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            {
              id: 'FIND-418',
              repo_id: 'repo-auth-gateway',
              cwe: 'CWE-89: SQL Injection',
              title: 'Raw SQL Query String Interpolation in user_query.py',
              severity: 'CRITICAL',
              scanner_name: 'Semgrep OSS',
              file_path: 'auth-gateway/src/dao/user_query.py',
              line_number: 42,
              status: 'open',
              confidence_score: 0.98,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
          ]),
        });
      }

      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({}),
      });
    }));
  });

  it('renders landing page on root route ("/")', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByText(/Detect source vulnerabilities/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Launch Security Console/i })).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: /Sign In/i })[0]).toBeInTheDocument();
  });

  it('renders login page on "/login"', () => {
    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: /Enterprise Security Sign-In/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Corporate Email/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Authenticate to Console/i })).toBeInTheDocument();
  });

  it('renders register page on "/register"', () => {
    render(
      <MemoryRouter initialEntries={['/register']}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: /Register AppSec Workspace/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Full Name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Work Email/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Initialize Workspace/i })).toBeInTheDocument();
  });

  it('renders dashboard with sidebar on "/dashboard"', async () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByRole('button', { name: 'Dashboard' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Repositories' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Findings' })).toBeInTheDocument();
    expect(screen.getByText(/Automated AppSec & Fix Verification Engine/i)).toBeInTheDocument();
  });

  it('renders repositories inventory and handles navigation on "/repositories"', async () => {
    render(
      <MemoryRouter initialEntries={['/repositories']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByText(/Production Repositories & Guardrails/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Ingest Repository|Register Repository/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Search repository/i)).toBeInTheDocument();
  });

  it('renders findings hub on "/findings"', async () => {
    render(
      <MemoryRouter initialEntries={['/findings']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByText(/Vulnerability Findings/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Search by title/i)).toBeInTheDocument();
  });

  it('renders fix verification center on "/verification"', () => {
    render(
      <MemoryRouter initialEntries={['/verification']}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByText(/AUTOMATED AST FIX VERIFICATION SUITE/i)).toBeInTheDocument();
  });

  it('renders evidence center on "/evidence"', () => {
    render(
      <MemoryRouter initialEntries={['/evidence']}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByText(/Compliance Frameworks & Cryptographic Proofs/i)).toBeInTheDocument();
  });

  it('renders settings on "/settings"', async () => {
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <App />
      </MemoryRouter>
    );

    expect(screen.getByText(/Security Governance & Application Settings/i)).toBeInTheDocument();
    expect(screen.getByText(/Strict AST Taint Verification/i)).toBeInTheDocument();
    expect(screen.getByText(/Zero Hardcoded Secrets Policy/i)).toBeInTheDocument();
  });

  it('renders finding details on "/findings/:id"', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/FIND-418']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByText(/AST Taint Trace Evidence/i)).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Run AI Analyst|Run Backend Triage|Re-analyze with AI/i })[0]).toBeInTheDocument();
    expect(screen.getByText(/AI Security Analyst/i)).toBeInTheDocument();
    expect(screen.getByText(/AI-Generated Security Analysis — Requires Human Review/i)).toBeInTheDocument();
  });
});
