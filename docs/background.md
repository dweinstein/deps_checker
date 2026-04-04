# Background

## Why This Tool Exists

`deps_checker` was built to quickly identify compromised npm packages in NowSecure SBOM data, especially across a large mobile app portfolio.

The current package set and bundled curated entries are informed by several notable supply-chain incidents:

1. [Major npm supply-chain attack, September 8, 2025](https://www.nowsecure.com/blog/2025/09/08/major-npm-supply-chain-attack-potential-impact-on-mobile-applications/)
2. [Second wave affecting 187 packages, September 16, 2025](https://www.nowsecure.com/blog/2025/09/16/new-npm-supply-chain-attack-hits-187-packages-heres-why-mobile-apps-are-still-at-risk/)
3. [Shai-Hulud 2.0 worm, November 2025](https://blog.gitguardian.com/shai-hulud-2/)
4. [Axios account takeover and malicious releases, March 31, 2026](https://socket.dev/blog/axios-npm-package-compromised)

The axios incident includes advisory [GHSA-fw8c-xr5c-95f9](https://github.com/advisories/GHSA-fw8c-xr5c-95f9). The malicious versions are `axios@1.14.1` and `axios@0.30.4`.

## Why Mobile Apps Are Still Exposed

Mobile applications often pull in JavaScript dependencies through:

- Hybrid frameworks such as React Native, Ionic, Cordova, and NativeScript
- Backend services and supporting APIs
- Build tooling and CI/CD dependencies

Compromised packages in those paths can:

- Steal credentials or tokens
- Intercept traffic
- Exfiltrate data
- Modify app behavior during build or runtime

## What This Tool Helps Teams Do

- Rapidly identify compromised package versions in assessed apps
- Scan many apps at once from the NowSecure GraphQL API
- Track exact malicious versions, not just package names
- Respond faster during active supply-chain incidents
