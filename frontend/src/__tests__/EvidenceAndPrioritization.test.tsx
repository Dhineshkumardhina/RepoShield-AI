import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EvidencePage } from '../pages/EvidencePage';
import { FindingDetailPage } from '../pages/FindingDetailPage';

describe('Contextual Risk Prioritization & Security Evidence Center', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url.includes('/api/v1/evidence/reports')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve({
            report_title: 'Security Findings Report — xerova/auth-gateway',
            repository_id: 'repo-auth-gateway',
            format: 'markdown',
            generated_at: new Date().toISOString(),
            content: '# RepoShield AI Security Findings Report\n\nChecks Not Performed:\n- DAST\n',
            metadata: { total_findings: 1 }
          })
        });
      }

      if (url.includes('/api/v1/evidence')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve([
            {
              id: 'ev_test_01',
              repository_id: 'repo-auth-gateway',
              finding_id: 'FIND-418',
              evidence_category: 'scanner_output',
              title: 'Semgrep OSS Raw AST Match',
              provenance: 'scanner_observed',
              tool_name: 'Semgrep OSS',
              tool_version: '1.78.0',
              content_hash: '9f81a7b8201a0bc178e24faeb9104cb99120adfe77890123cbfae1098234ab91',
              sanitized_payload: '{"match": "cursor.execute(query)"}',
              checks_not_performed: JSON.stringify(['Dynamic Runtime Taint Analysis (DAST): Not configured.']),
              recorded_at: new Date().toISOString(),
              created_at: new Date().toISOString()
            }
          ])
        });
      }

      if (url.includes('prioritization')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve({
            finding_id: 'FIND-418',
            original_scanner_severity: 'CRITICAL',
            contextual_priority: 'CRITICAL',
            priority_score: 95.0,
            evidence_completeness: 'PARTIAL',
            verification_status: 'NOT_TESTED',
            remediation_readiness: 'NO_VERIFIED_FIX',
            floor_protection_applied: true,
            investigation_recommendation: 'Inspect authorization checks',
            factors: [
              { name: 'Scanner Baseline: CRITICAL', impact: 85, rationale: 'Initial score from Semgrep OSS' },
              { name: 'Reachability: Unconfirmed', impact: 0, rationale: 'Missing call-graph proof' }
            ]
          })
        });
      }

      return Promise.resolve({
        ok: true,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: () => Promise.resolve({})
      });
    }));
  });

  it('renders Evidence Center with integrity notice and omission auditing', async () => {
    render(
      <MemoryRouter>
        <EvidencePage />
      </MemoryRouter>
    );

    // Compliance proofs title (from mock frameworks)
    expect(screen.getByText(/Compliance Frameworks & Cryptographic Proofs/i)).toBeInTheDocument();

    // Mandatory Evidence Integrity Notice
    expect(screen.getByText(/Evidence Integrity & Provenance Notice/i)).toBeInTheDocument();
    expect(screen.getByText(/Content hashes assist in detecting accidental alterations/i)).toBeInTheDocument();
    expect(screen.getByText(/Numerical priority scores represent contextual triage indices/i)).toBeInTheDocument();

    // Checks Not Performed section
    expect(screen.getByText(/Identified Checks Not Performed \(Omission Auditing\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Dynamic Taint \(DAST\)/i)).toBeInTheDocument();

    // Provenance badges
    // console.log("BODY:", document.body.innerHTML);
    expect(await screen.findAllByText(/SCANNER OBSERVED/i)).toBeDefined();
  });

  it('opens Evidence Payload modal showing SHA-256 hash and omission checks', async () => {
    render(
      <MemoryRouter>
        <EvidencePage />
      </MemoryRouter>
    );

    // Wait for live evidence item to resolve and render
    await screen.findByText('Semgrep OSS Raw AST Match');
    const inspectBtn = screen.getByRole('button', { name: /Inspect Payload/i });
    fireEvent.click(inspectBtn);

    // Modal title & content hash
    expect(await screen.findByText(/Cryptographic Content Hash \(SHA-256\)/i)).toBeInTheDocument();
    expect(screen.getByText(/9f81a7b8201a0bc178e24faeb9104cb99120adfe77890123cbfae1098234ab91/i)).toBeInTheDocument();
    expect(screen.getByText(/Sanitized Payload Excerpt \(Secrets Redacted\)/i)).toBeInTheDocument();

    // Close modal
    const closeBtns = screen.getAllByRole('button', { name: /Close/i });
    fireEvent.click(closeBtns[0]);

    await waitFor(() => {
      expect(screen.queryByText(/Cryptographic Content Hash \(SHA-256\)/i)).not.toBeInTheDocument();
    });
  });

  it('renders Finding Details with 4 separated risk prioritization dimensions', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/FIND-418']}>
        <Routes>
          <Route path="/findings/:id" element={<FindingDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    // Contextual Risk Prioritization Banner
    expect(await screen.findByText(/CONTEXTUAL RISK PRIORITIZATION & EVIDENCE BOUNDARY/i)).toBeInTheDocument();
    expect(screen.getByText(/Triage Metric • Not Probability of Exploitation/i)).toBeInTheDocument();

    // 4 Separated Dimensions
    expect(screen.getByText(/1\. Scanner Severity/i)).toBeInTheDocument();
    expect(screen.getByText(/2\. Contextual Priority/i)).toBeInTheDocument();
    expect(screen.getByText(/3\. Evidence Completeness/i)).toBeInTheDocument();
    expect(screen.getByText(/4\. Verification Status/i)).toBeInTheDocument();

    // Traceable factors
    expect(screen.getByText(/Traceable Scoring Factors:/i)).toBeInTheDocument();
    expect(screen.getByText(/Scanner Baseline:/i)).toBeInTheDocument();
    expect(screen.getByText(/Reachability:/i)).toBeInTheDocument();
  });
});
