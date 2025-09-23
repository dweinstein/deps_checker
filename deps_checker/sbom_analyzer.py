from typing import Dict, List, Any, Optional, Tuple
from .vuln_db import VulnerabilityDatabase


class SBOMAnalyzer:
    def __init__(self, vuln_db: VulnerabilityDatabase):
        self.vuln_db = vuln_db

    def analyze_sbom(self, sbom_items: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        results = {
            "critical": [],
            "warnings": []
        }

        for item in sbom_items:
            if not item:
                continue

            package_name = item.get("name", "").strip()
            version_value = item.get("version", "")
            version = version_value.strip() if version_value else ""
            source = item.get("source", "")

            if not package_name or not version:
                continue

            if self.vuln_db.is_vulnerable_exact(package_name, version):
                results["critical"].append({
                    "name": package_name,
                    "version": version,
                    "source": source,
                    "vulnerable_versions": self.vuln_db.get_vulnerable_versions(package_name),
                    "match_type": "exact"
                })
            elif self.vuln_db.has_vulnerable_package(package_name):
                results["warnings"].append({
                    "name": package_name,
                    "version": version,
                    "source": source,
                    "vulnerable_versions": self.vuln_db.get_vulnerable_versions(package_name),
                    "match_type": "package_name"
                })

        return results

    def extract_sbom_from_response(self, response: Dict[str, Any], debug: bool = False) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        metadata = {}
        sbom_items = []

        if debug:
            # In debug mode, let errors propagate
            data = response.get("data", {})
            auto = data.get("auto", {})
            application = auto.get("application", {})

            metadata["package_key"] = application.get("packageKey", "unknown")
            metadata["platform"] = application.get("platformType", "unknown")

            assessment = application.get("latestCompleteAssessment", {})
            if assessment:
                metadata["build_version"] = assessment.get("buildVersion", "unknown")
                report = assessment.get("report", {})

                sbom_finding = report.get("sbom", {})
                if sbom_finding and isinstance(sbom_finding, dict):
                    context = sbom_finding.get("context", {})
                    items = context.get("items", [])
                    if items:
                        sbom_items.extend(items)
                        # Output full SBOM in debug mode
                        import json
                        import sys
                        print("\n=== DEBUG: Full SBOM Data ===", file=sys.stderr)
                        print(f"Package: {metadata['package_key']}", file=sys.stderr)
                        print(f"Platform: {metadata['platform']}", file=sys.stderr)
                        print(f"Build Version: {metadata.get('build_version', 'unknown')}", file=sys.stderr)
                        print(f"Total SBOM Items: {len(items)}", file=sys.stderr)
                        print("\nSBOM Items:", file=sys.stderr)
                        print(json.dumps(items, indent=2), file=sys.stderr)
                        print("=== END SBOM Data ===\n", file=sys.stderr)
        else:
            # Normal mode with error handling
            try:
                data = response.get("data", {})
                auto = data.get("auto", {})
                application = auto.get("application", {})

                metadata["package_key"] = application.get("packageKey", "unknown")
                metadata["platform"] = application.get("platformType", "unknown")

                assessment = application.get("latestCompleteAssessment", {})
                if assessment:
                    metadata["build_version"] = assessment.get("buildVersion", "unknown")
                    report = assessment.get("report", {})

                    sbom_finding = report.get("sbom", {})
                    if sbom_finding and isinstance(sbom_finding, dict):
                        context = sbom_finding.get("context", {})
                        items = context.get("items", [])
                        if items:
                            sbom_items.extend(items)

            except Exception as e:
                import sys
                print(f"Error extracting SBOM from response: {e}", file=sys.stderr)
                if debug:
                    import json
                    print(f"Response: {json.dumps(response, indent=2)}", file=sys.stderr)

        return metadata, sbom_items

    def generate_summary(self, analysis_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        return {
            "total_critical": len(analysis_results.get("critical", [])),
            "total_warnings": len(analysis_results.get("warnings", [])),
            "has_vulnerabilities": len(analysis_results.get("critical", [])) > 0,
            "unique_vulnerable_packages": len(set(
                item["name"] for item in analysis_results.get("critical", [])
            )),
            "unique_warning_packages": len(set(
                item["name"] for item in analysis_results.get("warnings", [])
            ))
        }
