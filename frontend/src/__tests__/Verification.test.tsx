import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VerificationPage } from '../pages/VerificationPage';

describe('Fix Verification Engine Frontend Workspace', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string, options?: any) => {
      if (url.includes('/api/v1/verifications/validate-patch')) {
        const body = JSON.parse(options?.body || '{}');
        if (body.proposed_patch?.includes('etc/shadow') || body.proposed_patch?.includes('..')) {
          return Promise.resolve({
            ok: false,
            status: 400,
            headers: new Headers({ 'Content-Type': 'application/json' }),
            json: () => Promise.resolve({
              error: {
                message: 'Patch rejected: Path traversal attempt outside repository boundary: ../../../../etc/shadow',
                code: 'PATH_TRAVERSAL_REJECTED'
              }
            })
          });
        }
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve({
            is_valid: true,
            files: [
              {
                old_path: 'auth_gateway/dao/user_query.py',
                new_path: 'auth_gateway/dao/user_query.py',
                added_lines: 2,
                deleted_lines: 2,
                modified_lines_range: '10-14'
              }
            ],
            total_added: 2,
            total_deleted: 2,
            errors: [],
            warnings: []
          })
        });
      }

      if (url.includes('/api/v1/verifications') && options?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve({
            id: 'vr_test_exec_01',
            finding_id: 'FIND-418',
            baseline_hash: 'SHA256:4b91f092e038fa8167385a498b81347101adfa4792cb00a89104faeb19cb84f1',
            patched_hash: 'SHA256:7c82a194df110298a4421b8f1412fa09bb3310cbde12586144e05417ab9071cb',
            scanner_metadata: { 'Semgrep OSS': '1.45.0' },
            scanner_config: {},
            tests_executed: ['test_sql_injection_payload_is_neutralized'],
            test_results: { passed: 1 },
            original_finding_status: 'resolved',
            new_findings: [],
            execution_errors: [],
            started_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
            status: 'VERIFIED_AGAINST_DEFINED_CHECKS',
            reasons: ['Original finding FIND-418 was resolved and no new regressions were detected.'],
            missing_evidence: ['Dynamic database runtime taint tests not configured.'],
            evidence_references: ['aud_vr_test_exec_01'],
            patch_diff: '--- a/file.py\n+++ b/file.py',
            test_summary: '1 passed in 0.5s',
            limitations: ['Never claim universal security or mathematically proven correctness.'],
            evidence: []
          })
        });
      }

      if (url.includes('/api/v1/verifications')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([])
        });
      }

      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({})
      });
    }));
  });

  it('renders fix verification workspace with mandatory limitations banner', () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Suite Header
    expect(screen.getByText(/AUTOMATED AST FIX VERIFICATION SUITE/i)).toBeInTheDocument();
    expect(screen.getByText(/Fix Verification Queue & Test Regression Gates/i)).toBeInTheDocument();

    // Prominent Guardrails and Limitations Banner
    expect(screen.getByText(/Evidence-Based Fix Verification Engine — Guardrails & Limitations/i)).toBeInTheDocument();
    expect(screen.getByText(/A scanner finding disappearing does not prove that the vulnerability is impossible/i)).toBeInTheDocument();
    expect(screen.getByText(/Passing tests do not prove complete security/i)).toBeInTheDocument();
    expect(screen.getByText(/Never claim universal security or mathematically proven correctness/i)).toBeInTheDocument();
  });

  it('displays verification runs table with required evidence statuses', () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Should display runs with distinct evidence statuses
    expect(screen.getAllByText('VERIFIED_AGAINST_DEFINED_CHECKS')[0]).toBeInTheDocument();
    expect(screen.getAllByText('FAILED_VERIFICATION')[0]).toBeInTheDocument();
    expect(screen.getAllByText('INCONCLUSIVE')[0]).toBeInTheDocument();

    // Verify finding IDs and run references
    expect(screen.getByText('vr_sample_01')).toBeInTheDocument();
    expect(screen.getByText('vr_sample_02')).toBeInTheDocument();
  });

  it('opens Evidence Inspector modal with 5-step traceability', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Click "Inspect Evidence" on the first sample run
    const inspectButtons = screen.getAllByRole('button', { name: /Inspect Evidence/i });
    fireEvent.click(inspectButtons[0]);

    // Modal title & baseline hash
    expect(await screen.findByText(/Fix Verification Run Evidence/i)).toBeInTheDocument();

    // Before/After comparison check (default tab)
    expect(screen.getByText(/Cryptographic Baseline vs Patched Comparison/i)).toBeInTheDocument();
    expect(screen.getByText(/Isolated Test Suite Regression Analysis/i)).toBeInTheDocument();

    // Switch to 5-Step Verification Audit tab
    const auditTabBtn = screen.getByRole('button', { name: /5-Step Verification Audit/i });
    fireEvent.click(auditTabBtn);

    expect(screen.getByText(/STEP 1 — Baseline Established/i)).toBeInTheDocument();
    expect(screen.getByText(/STEP 2 & 3 — Safe Patch Handling & Isolated Workspace/i)).toBeInTheDocument();
    expect(screen.getByText(/STEP 4 — Before & After Comparison & Regression Gates/i)).toBeInTheDocument();
    expect(screen.getByText(/RESOLVED \(No Longer Reported\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Zero Regressions Detected/i)).toBeInTheDocument();
    expect(screen.getByText(/STEP 5 — Evidence-Based Conclusion & Traceable Rationale/i)).toBeInTheDocument();

    // Reasons & limitations displayed
    expect(screen.getAllByText(/Original finding FIND-418 was resolved and is no longer reported by Semgrep OSS/i)[0]).toBeInTheDocument();
    expect(screen.getByText(/Dynamic runtime taint flow with live database network cursor was not evaluated/i)).toBeInTheDocument();


    // Close modal
    const closeBtn = screen.getByRole('button', { name: /Close Inspector/i });
    fireEvent.click(closeBtn);

    await waitFor(() => {
      expect(screen.queryByText(/STEP 1 — Baseline Established/i)).not.toBeInTheDocument();
    });
  });

  it('opens Trigger Verification modal, validates patch safely, and detects file line changes', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Open Trigger modal
    const triggerBtn = screen.getByRole('button', { name: /Trigger Fix Verification/i });
    fireEvent.click(triggerBtn);

    expect(screen.getByText(/Trigger Fix Verification Engine/i)).toBeInTheDocument();

    // Click "Validate Patch Safely"
    const validateBtn = screen.getByRole('button', { name: /Validate Patch Safely/i });
    fireEvent.click(validateBtn);

    // Should render validation result
    expect(await screen.findByText(/Patch Parsing & Path Validation Passed/i)).toBeInTheDocument();
    expect(screen.getByText(/\+2 \/ -2 lines/i)).toBeInTheDocument();
    expect(screen.getByText(/Touched:/i)).toBeInTheDocument();
  });

  it('rejects path traversal patch during dry-run validation', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Open Trigger modal
    const triggerBtn = screen.getByRole('button', { name: /Trigger Fix Verification/i });
    fireEvent.click(triggerBtn);

    // Select Preset 4 (Path Traversal)
    const traversalPresetBtn = screen.getByRole('button', { name: /Preset 4: Malicious Path Traversal/i });
    fireEvent.click(traversalPresetBtn);

    // Ensure the textarea reflects the traversal diff
    const textarea = screen.getByPlaceholderText(/--- a\/path\/to\/file/i) as HTMLTextAreaElement;
    expect(textarea.value).toContain('../../../../etc/shadow');

    // Click "Validate Patch Safely"
    const validateBtn = screen.getByRole('button', { name: /Validate Patch Safely/i });
    fireEvent.click(validateBtn);

    // Should display rejection error
    expect(await screen.findByText(/Path traversal attempt outside repository boundary/i)).toBeInTheDocument();
  });
});
