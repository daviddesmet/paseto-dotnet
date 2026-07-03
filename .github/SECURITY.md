# Security Policy

## Supported Versions

Only the latest release of Paseto.Core published on [NuGet](https://www.nuget.org/packages/Paseto.Core) receives security updates.

| Version | Supported |
| ------- | --------- |
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/daviddesmet/paseto-dotnet/security/advisories/new).

Please include:

- A description of the issue and its impact
- Steps or a proof of concept to reproduce it
- Affected version(s)

You can expect an initial response within 7 days. Once the issue is confirmed, a fix will be developed and released, and the advisory published with credit to the reporter (unless you prefer to remain anonymous).

## Scope notes

- The strong-name key (`Key.snk`) is intentionally committed to the repository to allow reproducible builds. Strong naming is **not** a security boundary and the strong-name identity should not be treated as a trust signal; rely on NuGet package signing and provenance instead.
- Key generation and secure storage are the responsibility of the caller. Using weak, reused, or compromised keys breaks the security guarantees of the tokens produced by this library; this is inherent to the algorithms and not considered a vulnerability.
