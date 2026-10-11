import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { AiSecurityAnalystCard } from '../components/findings/AiSecurityAnalystCard';
import { AnalysisResult } from '../services/api';

describe('AiSecurityAnalystCard Component', () => {
  const mockAnalysis: AnalysisResult = {
    id: 'ANALYSIS-101',
    finding_id: 'FIND-418',
    vulnerability_category: 'CWE-89: SQL Injection',
    plain_language_explanation: 'User input is directly interpolated into a raw SQL query string without parameterized bindings.',
    likely_root_cause: 'String formatting f-string used in DAO query builder without parameter placeholders.',
    potential_impact: 'Full database read and write access, bypassing authentication and authorization controls.',
    relevant_code_evidence: [
      'cursor.execute(f"SELECT * FROM users WHERE tenant_id = \'{tenant_id}\'")',
      'tenant_id parameter from request query arguments'
    ],
    suggested_remediation: [
      'Replace f-string with parameterized query placeholders %s',
      'Pass parameters as a tuple: cursor.execute("SELECT ... WHERE tenant_id = %s", (tenant_id,))'
    ],
    suggested_targeted_tests: [
      'test_sql_injection_payload_in_tenant_id_rejected()',
      'test_normal_tenant_id_retrieves_expected_record()'
    ],
    missing_context: [
      'Router middleware authorization not captured in 30-line window'
    ],
    limitations: [
      'Static analysis only. Runtime database permission level cannot be verified.'
    ],
    ai_model: 'gemini-1.5-flash',
    analysis_timestamp: '2026-10-11T10:00:00Z',
    confidence: 'HIGH',
    is_exploitable_claim_supported: true,
    requires_human_review: true,
    user_authorized: true
  };

  it('renders AI Security Analyst Card with mandatory human review warning', () => {
    render(
      <AiSecurityAnalystCard
        analysis={mockAnalysis}
        isLoading={false}
        error={null}
        userAuthorized={true}
        onToggleAuthorization={vi.fn()}
        onRunAnalysis={vi.fn()}
      />
    );

    // Warning banner
    expect(screen.getByText(/AI-Generated Security Analysis — Requires Human Review/i)).toBeInTheDocument();
    expect(screen.getByText(/must be validated by security engineers prior to implementation/i)).toBeInTheDocument();

    // Model and metadata
    expect(screen.getByText('gemini-1.5-flash')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();

    // Exploitability status
    expect(screen.getByText(/Exploitability Supported by Static Flow/i)).toBeInTheDocument();

    // Plain-language explanation, root cause, impact
    expect(screen.getByText(/User input is directly interpolated into a raw SQL query string/i)).toBeInTheDocument();
    expect(screen.getByText(/String formatting f-string used in DAO query builder/i)).toBeInTheDocument();
    expect(screen.getByText(/Full database read and write access/i)).toBeInTheDocument();

    // Remediations and tests
    expect(screen.getByText(/Replace f-string with parameterized query placeholders/i)).toBeInTheDocument();
    expect(screen.getByText(/test_sql_injection_payload_in_tenant_id_rejected\(\)/i)).toBeInTheDocument();

    // Caveats
    expect(screen.getByText(/Router middleware authorization not captured/i)).toBeInTheDocument();
    expect(screen.getByText(/Static analysis only/i)).toBeInTheDocument();
  });

  it('displays exploitability unproven badge when claim is not supported', () => {
    const unprovenAnalysis: AnalysisResult = {
      ...mockAnalysis,
      is_exploitable_claim_supported: false,
    };

    render(
      <AiSecurityAnalystCard
        analysis={unprovenAnalysis}
        isLoading={false}
        error={null}
        userAuthorized={true}
        onToggleAuthorization={vi.fn()}
        onRunAnalysis={vi.fn()}
      />
    );

    expect(screen.getByText(/Exploitability Unproven \/ Context Incomplete/i)).toBeInTheDocument();
  });

  it('handles user authorization toggle state', () => {
    const onToggle = vi.fn();
    render(
      <AiSecurityAnalystCard
        analysis={null}
        isLoading={false}
        error={null}
        userAuthorized={false}
        onToggleAuthorization={onToggle}
        onRunAnalysis={vi.fn()}
      />
    );

    // Authorization hold message shown
    expect(screen.getByText(/Authorization Hold:/i)).toBeInTheDocument();
    expect(screen.getByText(/private repository content will not be sent/i)).toBeInTheDocument();

    // Checkbox interaction
    const checkbox = screen.getByRole('checkbox');
    expect(checkbox).not.toBeChecked();
    fireEvent.click(checkbox);
    expect(onToggle).toHaveBeenCalledWith(true);
  });

  it('renders error message when analysis engine encounters error', () => {
    render(
      <AiSecurityAnalystCard
        analysis={null}
        isLoading={false}
        error="Backend AI rate limit exceeded or connection timed out."
        userAuthorized={true}
        onToggleAuthorization={vi.fn()}
        onRunAnalysis={vi.fn()}
      />
    );

    expect(screen.getByText(/Analyst Service Notice:/i)).toBeInTheDocument();
    expect(screen.getByText(/Backend AI rate limit exceeded or connection timed out/i)).toBeInTheDocument();
  });

  it('renders loading spinner when analysis is in progress', () => {
    render(
      <AiSecurityAnalystCard
        analysis={null}
        isLoading={true}
        error={null}
        userAuthorized={true}
        onToggleAuthorization={vi.fn()}
        onRunAnalysis={vi.fn()}
      />
    );

    expect(screen.getByText(/Synthesizing AI Security Assessment.../i)).toBeInTheDocument();
  });
});
