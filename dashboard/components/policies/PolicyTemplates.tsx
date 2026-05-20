"use client";

// Hardcoded mirror of the 10 fixtures under schemas/fixtures/policy_*.yaml.
// Embedded inline (rather than fetched at runtime) because:
//   1. They never change without a schema bump (and a schema bump means we
//      update this file anyway).
//   2. Avoids a second round-trip from the editor for what is basically
//      static template content.
// Source of truth: /schemas/fixtures/policy_*.yaml. Keep in sync manually.

export interface PolicyTemplate {
  id: string;
  label: string;
  description: string;
  yaml: string;
}

export const POLICY_TEMPLATES: PolicyTemplate[] = [
  {
    id: "minimal",
    label: "Minimal",
    description: "Smallest valid policy — one invariant.",
    yaml: `# Minimum viable policy — version + agent + one invariant.
version: "1"
agent: minimal_agent
invariants:
  - "spend_total <= 1"
`,
  },
  {
    id: "banking_payment",
    label: "Banking — payment agent",
    description: "Strict budget, narrow tool allowlist, EU business hours.",
    yaml: `# Banking payment agent — strict budget, narrow tool allowlist, EU business hours.
version: "1"
agent: payment_agent_eu
description: >
  Initiates SEPA payments on behalf of corporate treasury. Hard cap per
  policy lifetime, only allowed to call the payment + ledger tools, and may
  only act during EU business hours.
binding:
  allowed_tools:
    - sepa_payment_initiate
    - ledger_read
    - fx_quote
  max_budget_usd: 5000
  data_scope:
    allow: [customer_owned, financial]
    deny: [pii, restricted]
  rate_limit:
    requests_per_minute: 30
  time_window:
    start: "09:00"
    end:   "18:00"
    timezone: "Europe/Paris"
  required_signatures:
    - role: human_approver
      threshold: 1
  delegation:
    max_depth: 0
    allowed_subagents: []
invariants:
  - "spend_total <= max_budget_usd"
  - "payment_currency in ('EUR', 'USD')"
  - "no_external_call_to(domain: 'competitor.com')"
metadata:
  created_at: "2026-05-17"
  author: "compliance@example.com"
  tags: [banking, eu-region, treasury]
`,
  },
  {
    id: "customer_support_chatbot",
    label: "Customer support chatbot",
    description: "High RPM, public-scope only.",
    yaml: `# Customer-support chatbot — high RPM, public-scope only.
version: "1"
agent: support_chatbot
description: >
  Front-line customer support assistant. High request volume, but strictly
  scoped to public-facing data and a small toolset.
binding:
  allowed_tools:
    - kb_search
    - ticket_create
    - http_get
  max_budget_usd: 200
  data_scope:
    allow: [public]
    deny: [pii, financial, restricted]
  rate_limit:
    requests_per_minute: 600
  delegation:
    max_depth: 0
    allowed_subagents: []
invariants:
  - "rate_limit_compliant"
  - "no_pii_in_output"
metadata:
  created_at: "2026-01-15"
  author: "cx-ops@example.com"
  tags: [support, chatbot, public-scope]
`,
  },
  {
    id: "data_analyst",
    label: "Data analyst",
    description: "PII deny, aggregate queries only.",
    yaml: `# Data analyst agent — PII deny, aggregate queries only.
version: "1"
agent: data_analyst_agent
description: >
  Runs analytics over the warehouse. Must operate on aggregates only and
  must never read PII columns directly.
binding:
  allowed_tools:
    - warehouse_query
    - chart_render
    - export_csv
  max_budget_usd: 100
  data_scope:
    allow: [customer_owned, public]
    deny: [pii, restricted]
  rate_limit:
    requests_per_minute: 90
  time_window:
    start: "06:00"
    end:   "22:00"
    timezone: "Europe/Paris"
  delegation:
    max_depth: 0
    allowed_subagents: []
invariants:
  - "query_is_aggregate"
  - "row_count_returned >= 100 or aggregate_only"
  - "data_classification != 'restricted'"
metadata:
  created_at: "2026-04-04"
  author: "data-platform@example.com"
  tags: [analytics, aggregate-only, pii-deny]
`,
  },
  {
    id: "devtools_codegen",
    label: "Devtools codegen",
    description: "Sandboxed tools only, no external network calls.",
    yaml: `# Devtools codegen agent — sandboxed tools only, no external network calls.
version: "1"
agent: codegen_assistant
description: >
  Generates patches and runs the test suite inside an isolated sandbox.
  Must never reach external networks or escalate privileges.
binding:
  allowed_tools:
    - file_read
    - file_write
    - cargo_test
    - run_sandboxed
  max_budget_usd: 50
  rate_limit:
    requests_per_minute: 120
  delegation:
    max_depth: 0
    allowed_subagents: []
invariants:
  - "no_external_call_to(domain: '*')"
  - "sandbox_required(tool: 'run_sandboxed')"
  - "spend_total <= max_budget_usd"
metadata:
  created_at: "2026-03-01"
  author: "platform@example.com"
  tags: [devtools, codegen, sandbox]
`,
  },
  {
    id: "healthcare_records",
    label: "Healthcare records",
    description: "PII deny, 2-of-3 clinician signatures.",
    yaml: `# Healthcare records agent — PII deny, 2-of-3 clinician signatures.
version: "1"
agent: healthcare_records_assistant
description: >
  Summarises EHR fragments for clinicians. Must never expose raw PII or
  restricted records, and any export operation requires 2-of-3 clinician
  signatures.
binding:
  allowed_tools:
    - ehr_query
    - de_identify
    - aggregate_stats
  data_scope:
    allow: [customer_owned]
    deny: [pii, restricted, financial]
  rate_limit:
    requests_per_minute: 20
  required_signatures:
    - role: clinician
      threshold: 2
  delegation:
    max_depth: 1
    allowed_subagents: [summarize_agent]
invariants:
  - "data_classification != 'restricted'"
  - "exports_require_signatures(role: 'clinician', threshold: 2)"
  - "no_raw_pii_in_output"
metadata:
  created_at: "2026-04-12"
  author: "ciso@hospital.example"
  tags: [healthcare, hipaa, pii-deny]
`,
  },
  {
    id: "legal_review",
    label: "Legal review",
    description: "1-of-2 partner signature, no external counsel calls.",
    yaml: `# Legal review agent — 1-of-2 partner signature, no external counsel calls.
version: "1"
agent: legal_review_agent
description: >
  Assists with internal legal review of contracts. Any outbound action
  requires at least one partner signature; the agent must never contact
  external counsel directly.
binding:
  allowed_tools:
    - contract_read
    - redline
    - clause_lookup
  max_budget_usd: 300
  data_scope:
    allow: [customer_owned]
    deny: [pii, restricted]
  rate_limit:
    requests_per_minute: 15
  required_signatures:
    - role: partner
      threshold: 1
  delegation:
    max_depth: 1
    allowed_subagents: [clause_search_agent]
invariants:
  - "no_external_call_to(domain: '*.law')"
  - "outbound_requires_partner_signature"
  - "spend_total <= max_budget_usd"
metadata:
  created_at: "2026-05-01"
  author: "legal-ops@example.com"
  tags: [legal, partner-sig, internal-only]
`,
  },
  {
    id: "marketing_content",
    label: "Marketing content",
    description: "Posts only to approved domains.",
    yaml: `# Marketing content agent — only posts to approved domains.
version: "1"
agent: marketing_content_agent
description: >
  Drafts and posts marketing copy. Posts only to a vetted set of company
  domains; never reaches third-party social platforms directly.
binding:
  allowed_tools:
    - draft_copy
    - cms_publish
    - asset_lookup
  max_budget_usd: 150
  data_scope:
    allow: [public, customer_owned]
    deny: [pii, restricted]
  rate_limit:
    requests_per_minute: 30
  time_window:
    start: "07:00"
    end:   "22:00"
    timezone: "Europe/Paris"
  required_signatures:
    - role: marketing_reviewer
      threshold: 1
  delegation:
    max_depth: 0
    allowed_subagents: []
invariants:
  - "posting_domain in ('example.com', 'blog.example.com', 'press.example.com')"
  - "allowed_domain_only"
  - "spend_total <= max_budget_usd"
metadata:
  created_at: "2026-03-22"
  author: "brand-ops@example.com"
  tags: [marketing, content, domain-allowlist]
`,
  },
  {
    id: "research_assistant",
    label: "Research assistant",
    description: "Broad read, no write, daytime only.",
    yaml: `# Research assistant — broad read, no write, daytime only.
version: "1"
agent: research_assistant
description: >
  Reads public sources, summarises findings, never writes anywhere. Active
  only during business hours so reviewers are around.
binding:
  allowed_tools:
    - http_get
    - search
    - summarize
    - cite
  max_budget_usd: 25
  data_scope:
    allow: [public]
    deny: [pii, financial, restricted]
  rate_limit:
    requests_per_minute: 60
  time_window:
    start: "08:00"
    end:   "20:00"
    timezone: "Europe/Paris"
  delegation:
    max_depth: 1
    allowed_subagents: [search_agent, summarize_agent]
invariants:
  - "spend_total <= max_budget_usd"
  - "tool_class(tool) == 'read_only'"
metadata:
  created_at: "2026-02-20"
  author: "research-lead@example.com"
  tags: [research, read-only, daytime]
`,
  },
  {
    id: "treasury_ops",
    label: "Treasury ops",
    description: "Multi-sig + strict daily cap.",
    yaml: `# Treasury operations — multi-sig + strict daily cap.
version: "1"
agent: treasury_ops_agent
description: >
  Executes treasury moves between corporate accounts. Strict daily cap and
  two independent role signatures required for every outbound transfer.
binding:
  allowed_tools:
    - account_balance_read
    - internal_transfer
    - fx_quote
    - audit_log_write
  max_budget_usd: 250000
  data_scope:
    allow: [customer_owned, financial]
    deny: [pii, restricted]
  rate_limit:
    requests_per_minute: 10
  time_window:
    start: "07:30"
    end:   "19:30"
    timezone: "Europe/Paris"
  required_signatures:
    - role: treasury_officer
      threshold: 1
    - role: cfo_delegate
      threshold: 1
  delegation:
    max_depth: 0
    allowed_subagents: []
invariants:
  - "spend_total <= max_budget_usd"
  - "daily_outflow_total <= 250000"
  - "transfer_requires(roles: ['treasury_officer', 'cfo_delegate'])"
metadata:
  created_at: "2026-05-10"
  author: "treasury@example.com"
  tags: [treasury, multi-sig, daily-cap]
`,
  },
];

interface PolicyTemplatesProps {
  onPick: (yaml: string) => void;
  disabled?: boolean;
}

export function PolicyTemplates({ onPick, disabled }: PolicyTemplatesProps) {
  return (
    <div className="flex items-center gap-2">
      <label
        htmlFor="policy-template-picker"
        className="text-sm text-[var(--text-muted)]"
      >
        Template
      </label>
      <select
        id="policy-template-picker"
        disabled={disabled}
        defaultValue=""
        className="bg-[var(--bg-surface)] border border-[var(--border)] rounded px-3 py-1.5 text-sm text-[var(--text-secondary)] disabled:opacity-40"
        onChange={(e) => {
          const tpl = POLICY_TEMPLATES.find((t) => t.id === e.target.value);
          if (tpl) onPick(tpl.yaml);
          e.target.value = "";
        }}
      >
        <option value="" disabled>
          Load template…
        </option>
        {POLICY_TEMPLATES.map((t) => (
          <option key={t.id} value={t.id}>
            {t.label}
          </option>
        ))}
      </select>
    </div>
  );
}
