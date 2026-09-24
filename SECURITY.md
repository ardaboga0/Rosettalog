# Security policy

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's private vulnerability reporting instead:

1. Open the repository's **Security** tab
   (<https://github.com/ardaboga0/Rosettalog/security>).
2. Click **Report a vulnerability**.
3. Describe the problem, the affected version or commit, and a minimal **synthetic**
   reproduction.

Only the maintainer and you can see the report. We aim to acknowledge reports within 5 working
days and will coordinate a fix and disclosure with you.

In scope, for example:

- Parsing untrusted input (LSX XML, sample YAML): XXE, entity expansion, resource exhaustion.
- Generated target content that is *unsafe* rather than merely incomplete (for example, output
  that could inject into a SIEM configuration beyond the intended stanza or function).
- A translation that is reported as FULL but silently changes detection logic. We treat this as
  a security-relevant bug.

## Handling your data

Rosettalog runs locally and makes no network calls. Migration reports can contain regexes and
sample log lines, so review them before sharing. When filing issues, share only minimal,
**synthetic** reproductions and never real customer logs.
