// Note-based procedures for the recurring CTI loops. They are ordinary notes, so
// Executable Runbooks can run them step by step and keep a receipt per run.

export interface CtiRunbook { title: string; markdown: string }

export const CTI_RUNBOOKS: CtiRunbook[] = [
  {
    title: 'CTI runbook: pivot an identity',
    markdown: `# CTI runbook: pivot an identity

Use when a new handle, email, wallet or account turns up.

- [ ] Search **Identities** for the value (defanged input works) before doing anything else
- [ ] Open the identity's **Enrichment** panel and read every prior lookup — do not repeat one
- [ ] Run the missing lookups (GitHub/GitLab, search engine, blockchain explorer, breach data) and log each as enrichment
- [ ] Create every new identity found and link it with \`alias-of\` to the identity it aliases
- [ ] Link the cluster to its actor with \`attributed-to\` and set the confidence
- [ ] Check **Unattributed identities** is down by the identities you just attributed
- [ ] Update the lead that started this: outcome and next step
`,
  },
  {
    title: 'CTI runbook: triage new C2',
    markdown: `# CTI runbook: triage new C2

Use when a watch or a sample reveals new command-and-control, blob-host or dead-drop infrastructure.

- [ ] Search **Infrastructure** for the value and its rotation siblings
- [ ] Create or update the infrastructure record with kind, status (live/dead), hosting, ASN and registrar
- [ ] Link it to the previous host with \`rotation-of\`, and to the malware that talks to it with \`communicates-with\`
- [ ] Log urlscan, passive DNS and certificate-transparency lookups as enrichment
- [ ] Create the shareable indicator(s) with TLP and a valid-until date, linked with \`based-on\`
- [ ] Add a watch for the next rotation if one does not exist
- [ ] Decide whether a takedown disclosure is needed and open one if so
`,
  },
  {
    title: 'CTI runbook: prepare a disclosure capsule',
    markdown: `# CTI runbook: prepare a disclosure capsule

Use before sending a report or takedown request to a vendor, registrar, SEAL or law enforcement.

- [ ] Create the disclosure with recipient, type and the TLP ceiling the recipient may receive
- [ ] Link it with \`concerns\` to every actor, campaign, infrastructure and indicator in scope
- [ ] Confirm victims are excluded, or included only as redacted records with consent
- [ ] Build the capsule and review the STIX objects it lists
- [ ] Record the capsule SHA-256 in the message to the recipient
- [ ] Mark the disclosure sent, then acknowledged or actioned as replies arrive
`,
  },
  {
    title: 'CTI runbook: weekly what-changed review',
    markdown: `# CTI runbook: weekly what-changed review

- [ ] Open the **CTI Dashboard** and read *What changed* for the last 7 days
- [ ] Clear **Unhealthy watches**: fix the runner or pause the watch
- [ ] Work through **Stale leads**: close, re-prioritise or record the next step
- [ ] Review **Expiring indicators** and extend or revoke them
- [ ] Re-check **Live C2** and mark dead infrastructure dead
- [ ] Notify any **Unnotified victims** whose exposure is confirmed
`,
  },
];
