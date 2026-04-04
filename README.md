# NowSecure SBOM Vulnerability Checker

Scan the latest complete assessment for one app or your entire NowSecure portfolio and flag known risky SDK and package versions in SBOM data.

## Why This Tool Exists

This tool exists because the recent npm supply-chain attack timeline made fast portfolio-wide SBOM checks operationally important, not just nice to have:

1. September 8, 2025: the first major wave compromised high-download packages such as `chalk`, `debug`, and `ansi-styles`.
2. September 16, 2025: a second wave hit 187 additional packages, including packages adjacent to mobile development ecosystems.
3. November 2025: Shai-Hulud 2.0 expanded the threat with a self-propagating npm worm affecting hundreds of packages.
4. March 31, 2026: the axios compromise introduced malicious `axios@1.14.1` and `axios@0.30.4` releases.

For mobile teams, those incidents matter because risky JavaScript dependencies can enter through hybrid frameworks, backend services, or build tooling, and they often need to be checked across many apps quickly.

## Quick Start

### Requirements

- Python 3.7+
- NowSecure API key
- Network access if you use `--fetch-shai-hulud`
- No runtime dependencies beyond the Python standard library

### Install

```bash
git clone https://github.com/dweinstein/deps_checker.git
cd deps_checker
python3 -m pip install -e .
```

You can also run the CLI directly from source:

```bash
python3 -m deps_checker.cli --help
```

### Most Common Use Case

Scan every app in your account, using each app's latest complete assessment and the latest remote compromised-package data:

```bash
export NS_API_KEY="your-api-key"
check-sbom --all-app-refs --fetch-shai-hulud
```

`--fetch-shai-hulud` pulls the upstream Shai-Hulud 2.0 package list and merges the bundled curated entries in [`deps_checker/data/vulnerable.txt`](./deps_checker/data/vulnerable.txt), so newer cases such as the March 31, 2026 axios compromise are still checked.

For pipeline-friendly output:

```bash
check-sbom --all-app-refs --fetch-shai-hulud --format json > results.json
```

If you want a fully local vulnerability source instead of the live fetch:

```bash
check-sbom --all-app-refs --vuln-db deps_checker/data/vulnerable.txt
```

## What The Tool Does

- Pulls the latest complete assessment SBOM for each requested app
- Checks packages against known compromised versions
- Reports exact-version hits as `CRITICAL`
- Reports package-name-only matches as `WARNING`
- Supports single-app, batch, and full-account scans
- Outputs text, JSON, or CSV

## Other Common Inputs

- Single app: `check-sbom --ref "<uuid>" --fetch-shai-hulud`
- Several apps: `check-sbom --refs "<uuid1>" "<uuid2>" --fetch-shai-hulud`
- UUIDs from file: `check-sbom --refs-file example_refs.txt --fetch-shai-hulud`

Use `--api-key` if you do not want to set `NS_API_KEY`.

## Exit Behavior

- `0`: no vulnerabilities found
- `1`: one or more vulnerabilities found
- `1`: startup/runtime failure before results are produced

In normal mode, per-app query errors are included in the output payload instead of aborting the whole batch. Use `--debug` if you want exceptions to propagate.

## Additional Docs

- [CLI usage, input modes, output formats, and CI notes](./docs/usage.md)
- [Vulnerability data sources and file formats](./docs/vulnerability-data.md)
- [Python library usage](./docs/python-library.md)
- [Background on the tracked supply-chain attacks](./docs/background.md)
