#!/usr/bin/env python3

import argparse
import json
import os
import sys
from typing import List, Dict, Any, Optional

from graphql_client import GraphQLClient, GraphQLError
from vuln_db import VulnerabilityDatabase
from sbom_analyzer import SBOMAnalyzer


SBOM_QUERY = """
query($ref: UUID!) {
  auto {
    application(ref: $ref) {
      packageKey
      platformType
      latestCompleteAssessment {
        buildVersion
        report {
          sbom: finding(checkId: app_sbom) {
            checkId
            context {
              items
            }
          }
        }
      }
    }
  }
}
"""


class SBOMChecker:
    def __init__(self, api_key: str, endpoint: str = "https://api.nowsecure.com/graphql"):
        self.client = GraphQLClient(endpoint, api_key)
        self.vuln_db = VulnerabilityDatabase()
        self.analyzer = SBOMAnalyzer(self.vuln_db)

    def check_application(self, ref: str, debug: bool = False) -> Dict[str, Any]:
        if debug:
            # In debug mode, let errors propagate for easier debugging
            response = self.client.execute_query(SBOM_QUERY, {"ref": ref})
            metadata, sbom_items = self.analyzer.extract_sbom_from_response(response, debug=True)
            analysis = self.analyzer.analyze_sbom(sbom_items)
            summary = self.analyzer.generate_summary(analysis)

            return {
                "ref": ref,
                "metadata": metadata,
                "sbom_count": len(sbom_items),
                "analysis": analysis,
                "summary": summary,
                "error": None
            }

        # Normal mode with error handling
        try:
            response = self.client.execute_query(SBOM_QUERY, {"ref": ref})
            metadata, sbom_items = self.analyzer.extract_sbom_from_response(response)
            analysis = self.analyzer.analyze_sbom(sbom_items)
            summary = self.analyzer.generate_summary(analysis)

            return {
                "ref": ref,
                "metadata": metadata,
                "sbom_count": len(sbom_items),
                "analysis": analysis,
                "summary": summary,
                "error": None
            }

        except GraphQLError as e:
            return {
                "ref": ref,
                "error": str(e),
                "metadata": {},
                "analysis": {"critical": [], "warnings": []},
                "summary": {}
            }
        except Exception as e:
            return {
                "ref": ref,
                "error": f"Unexpected error: {str(e)}",
                "metadata": {},
                "analysis": {"critical": [], "warnings": []},
                "summary": {}
            }

    def check_multiple_applications(self, refs: List[str], debug: bool = False) -> List[Dict[str, Any]]:
        results = []
        for i, ref in enumerate(refs, 1):
            print(f"Processing {i}/{len(refs)}: {ref}", file=sys.stderr)
            result = self.check_application(ref, debug=debug)
            results.append(result)
        return results

    def format_text_output(self, results: List[Dict[str, Any]], verbose: bool = False) -> str:
        output = []
        total_apps = len(results)
        vulnerable_apps = sum(1 for r in results if r["summary"].get("has_vulnerabilities", False))

        output.append("=" * 80)
        output.append(f"SBOM Vulnerability Check Results")
        output.append(f"Total Applications Scanned: {total_apps}")
        output.append(f"Applications with Critical Vulnerabilities: {vulnerable_apps}")
        output.append("=" * 80)
        output.append("")

        for result in results:
            ref = result["ref"]
            metadata = result["metadata"]
            analysis = result["analysis"]
            summary = result["summary"]
            error = result.get("error")

            output.append(f"Application Ref: {ref}")

            if error:
                output.append(f"  ERROR: {error}")
                output.append("")
                continue

            output.append(f"  Package: {metadata.get('package_key', 'unknown')}")
            output.append(f"  Platform: {metadata.get('platform', 'unknown')}")
            output.append(f"  Total SBOM Items: {result.get('sbom_count', 0)}")

            critical = analysis.get("critical", [])
            warnings = analysis.get("warnings", [])

            if critical:
                output.append(f"\n  CRITICAL - Exact vulnerable version matches ({len(critical)}):")
                for item in critical:
                    output.append(f"    • {item['name']} v{item['version']}")
                    output.append(f"      Known vulnerable versions: {', '.join(item['vulnerable_versions'])}")
                    if verbose and item.get('source'):
                        output.append(f"      Source: {item['source']}")

            if warnings:
                output.append(f"\n  WARNING - Package name matches ({len(warnings)}):")
                for item in warnings:
                    output.append(f"    • {item['name']} {item['version']}")
                    output.append(f"      Known vulnerable versions: {', '.join(item['vulnerable_versions'])}")
                    if verbose and item.get('source'):
                        output.append(f"      Source: {item['source']}")

            if not critical and not warnings:
                output.append("  ✓ No vulnerable packages detected")

            output.append("")
            output.append("-" * 80)
            output.append("")

        return "\n".join(output)

    def format_json_output(self, results: List[Dict[str, Any]]) -> str:
        return json.dumps(results, indent=2)

    def format_csv_output(self, results: List[Dict[str, Any]]) -> str:
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Application Ref",
            "Package Key",
            "Platform",
            "Vulnerability Type",
            "Package Name",
            "Current Version",
            "Vulnerable Versions",
            "Source"
        ])

        for result in results:
            ref = result["ref"]
            metadata = result["metadata"]
            analysis = result["analysis"]

            for vuln_type, items in [("CRITICAL", analysis.get("critical", [])),
                                     ("WARNING", analysis.get("warnings", []))]:
                for item in items:
                    writer.writerow([
                        ref,
                        metadata.get("package_key", ""),
                        metadata.get("platform", ""),
                        vuln_type,
                        item.get("name", ""),
                        item.get("version", ""),
                        ", ".join(item.get("vulnerable_versions", [])),
                        item.get("source", "")
                    ])

            if not analysis.get("critical") and not analysis.get("warnings"):
                writer.writerow([
                    ref,
                    metadata.get("package_key", ""),
                    metadata.get("platform", ""),
                    "NONE",
                    "",
                    "",
                    "",
                    ""
                ])

        return output.getvalue()


def main():
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

    refs = []
    if args.ref:
        refs = [args.ref]
    elif args.refs:
        refs = args.refs
    elif args.refs_file:
        try:
            with open(args.refs_file, 'r') as f:
                refs = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: File not found: {args.refs_file}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file {args.refs_file}: {e}", file=sys.stderr)
            sys.exit(1)

    if not refs:
        print("Error: No application references provided", file=sys.stderr)
        sys.exit(1)

    checker = SBOMChecker(args.api_key, args.endpoint)

    if args.vuln_db:
        try:
            checker.vuln_db.load_from_file(args.vuln_db)
        except Exception as e:
            print(f"Error loading vulnerability database: {e}", file=sys.stderr)
            sys.exit(1)

    if args.debug:
        # Dump vulnerability database in debug mode
        checker.vuln_db.dump_to_stderr()

    results = checker.check_multiple_applications(refs, debug=args.debug)

    if args.format == "json":
        output = checker.format_json_output(results)
    elif args.format == "csv":
        output = checker.format_csv_output(results)
    else:
        output = checker.format_text_output(results, args.verbose)

    print(output)

    vulnerable_count = sum(1 for r in results if r["summary"].get("has_vulnerabilities", False))
    sys.exit(1 if vulnerable_count > 0 else 0)


if __name__ == "__main__":
    main()
