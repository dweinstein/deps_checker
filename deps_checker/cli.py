#!/usr/bin/env python3
"""Command-line interface for the NowSecure SBOM vulnerability checker."""

import argparse
import json
import os
import sys
from typing import List, Dict, Any

from .checker import SBOMChecker


def format_text_output(result: Dict[str, Any], verbose: bool = False) -> str:
    """Format result as human-readable text."""
    lines = []

    lines.append(f"Application Ref: {result['ref']}")

    if 'error' in result:
        lines.append(f"  ERROR: {result['error']}")
        return '\n'.join(lines) + '\n'

    metadata = result.get('metadata', {})
    if metadata.get('package_key'):
        lines.append(f"  Package: {metadata['package_key']}")
    if metadata.get('platform'):
        lines.append(f"  Platform: {metadata['platform']}")

    lines.append(f"  Total SBOM Items: {result['sbom_count']}")

    analysis = result.get('analysis', {})
    critical = analysis.get('critical', [])
    warnings = analysis.get('warnings', [])

    if critical:
        lines.append(f"\n  CRITICAL - Exact vulnerable version matches ({len(critical)}):")
        for item in critical:
            lines.append(f"    • {item['name']} v{item['version']}")
            if verbose:
                lines.append(f"      Known vulnerable versions: {', '.join(item['vulnerable_versions'])}")

    if warnings:
        lines.append(f"\n  WARNING - Package name matches ({len(warnings)}):")
        for item in warnings:
            lines.append(f"    • {item['name']} v{item['version']}")
            if verbose:
                lines.append(f"      Known vulnerable versions: {', '.join(item['vulnerable_versions'])}")

    if not critical and not warnings:
        lines.append("\n  ✓ No known vulnerabilities found")

    return '\n'.join(lines) + '\n'


def format_csv_output(results: List[Dict[str, Any]]) -> str:
    """Format results as CSV."""
    lines = ["ref,package_key,platform,sbom_count,critical_count,warning_count,error"]

    for result in results:
        ref = result['ref']
        error = result.get('error', '')
        metadata = result.get('metadata', {})
        package_key = metadata.get('package_key', '')
        platform = metadata.get('platform', '')
        sbom_count = result.get('sbom_count', 0)

        summary = result.get('summary', {})
        critical_count = summary.get('total_critical', 0)
        warning_count = summary.get('total_warnings', 0)

        lines.append(f'"{ref}","{package_key}","{platform}",{sbom_count},{critical_count},{warning_count},"{error}"')

    return '\n'.join(lines)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Check NowSecure SBOM for vulnerable dependencies"
    )

    parser.add_argument(
        "--api-key",
        help="NowSecure API key (or set NS_API_KEY environment variable)",
        default=os.environ.get("NS_API_KEY")
    )

    parser.add_argument(
        "--endpoint",
        help="GraphQL endpoint URL",
        default="https://api.nowsecure.com/graphql"
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--ref",
        help="Single application reference UUID"
    )
    input_group.add_argument(
        "--refs",
        nargs="+",
        help="Multiple application reference UUIDs"
    )
    input_group.add_argument(
        "--refs-file",
        help="File containing application reference UUIDs (one per line)"
    )

    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include additional details in output"
    )

    parser.add_argument(
        "--vuln-db",
        required=True,
        help="Path to vulnerability database file (JSON or TSV format). Use 'vulnerable.txt' for the full database."
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode (errors will not be caught, useful for debugging)"
    )

    args = parser.parse_args()

    if not args.api_key:
        print("Error: API key required. Use --api-key or set NS_API_KEY environment variable",
              file=sys.stderr)
        sys.exit(1)

    # Collect references
    refs = []
    if args.ref:
        refs = [args.ref]
    elif args.refs:
        refs = args.refs
    elif args.refs_file:
        try:
            checker = SBOMChecker(args.api_key, args.endpoint)
            refs = checker.read_refs_from_file(args.refs_file)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    if not refs:
        print("Error: No application references provided", file=sys.stderr)
        sys.exit(1)

    # Initialize checker and load vulnerability database
    try:
        checker = SBOMChecker(args.api_key, args.endpoint)
        checker.load_vulnerability_database(args.vuln_db)
    except Exception as e:
        print(f"Error initializing checker or loading vulnerability database: {e}", file=sys.stderr)
        sys.exit(1)

    # Check applications
    try:
        results = checker.check_multiple_applications(refs, debug=args.debug)
    except Exception as e:
        print(f"Error checking applications: {e}", file=sys.stderr)
        sys.exit(1)

    # Output results
    if args.format == "json":
        print(json.dumps(results, indent=2))
    elif args.format == "csv":
        print(format_csv_output(results))
    else:  # text format
        for result in results:
            print(format_text_output(result, verbose=args.verbose))

    # Exit with appropriate code
    has_vulnerabilities = any(
        result.get('summary', {}).get('has_vulnerabilities', False)
        for result in results
    )

    if has_vulnerabilities:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()