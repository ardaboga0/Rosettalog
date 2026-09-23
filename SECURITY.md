# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. We aim to acknowledge reports within 5 working days.

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
