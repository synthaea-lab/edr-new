# server/integrations — SOAR, Ticketing, Paging

Where cases meet the organization's workflow (distinct from `export/`, which streams
telemetry to SIEMs — this is bidirectional case workflow):

- **Ticketing**: cases open/update Jira / ServiceNow issues with two-way status sync
  (close the ticket → annotate the case, resolve the case → resolve the ticket)
- **Paging**: severity-threshold routing to PagerDuty/Opsgenie/Slack with dedup by
  case (a case pages once, not per detection)
- **SOAR/webhooks**: signed outbound webhooks on case lifecycle events, and a small
  inbound action API (acknowledge, annotate, trigger an EXISTING policy-gated
  playbook) — integrations get no capability the console does not have, and every
  inbound action is authenticated and audited like an analyst's.
