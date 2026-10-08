# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private reporting instead: **Security → Report a vulnerability** on this
repository (GitHub Security Advisories). That opens a private thread with the maintainers
and gives us a coordinated-disclosure window.

If that is not available, open a minimal issue that contains *no* exploit details and ask
for a contact channel.

Please include:

- NetWatch-Lite version (`netwatch --version`) and Python version
- What you expected to happen vs. what happened
- A minimal PCAP / auth-log sample that reproduces it (synthetic data only — never real
  captures or logs from a production network, see below)
- Impact: crash, wrong verdict on attacker traffic, alert suppression, code execution, ...

## Scope

**In scope**

- Code execution, path traversal, ReDoS, XML/JSON/CSV parsing bugs
- A crafted PCAP or auth log that crashes the analyser or makes it silently drop events
- Incorrect severity classification that would make a real attack look benign
- HTML report issues: script injection through alert data, CSS/HTML injection, unsafe links
- Secrets leaking into a report, JSON, CSV or a webhook payload

**Out of scope**

- False positives/negatives caused by default thresholds (that is what `rules/default.yaml`
  and [docs/detections.md](docs/detections.md) are for)
- Findings that already require the attacker to control the machine being analysed
- Missing detections for techniques the roadmap does not claim to cover

## Handling real data

This tool processes network captures and authentication logs — both are sensitive.

- Never attach a real capture or log to an issue, a pull request, a test fixture or a demo.
  The repository `.gitignore` blocks `*.real.pcap` and `private/` on purpose.
- Use `netwatch demo` to generate synthetic traffic for reproductions.
- Redact hostnames, user names, public IPs and tokens before pasting output.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ actively patched |
| < 0.1   | ❌ pre-release |

## Disclosure timeline

We aim to acknowledge reports within **7 days**, ship a fix or a mitigation within
**30 days** for issues with a real-world impact, and credit reporters who want to be named.
