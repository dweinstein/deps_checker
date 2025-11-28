"""Main business logic for SBOM vulnerability checking."""

from typing import List, Dict, Any, Optional

from .graphql_client import GraphQLClient, GraphQLError
from .vuln_db import VulnerabilityDatabase
from .sbom_analyzer import SBOMAnalyzer
from .shai_hulud_fetcher import ShaiHuludFetcher


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

APPLICATIONS_QUERY = """
query {
  auto {
    applications {
      ref
      packageKey
      platformType
    }
  }
}
"""


class SBOMChecker:
    """Main class for checking SBOM data against vulnerability database."""

    def __init__(self, api_key: str, endpoint: str = "https://api.nowsecure.com/graphql"):
        self.client = GraphQLClient(endpoint, api_key)
        self.vuln_db = VulnerabilityDatabase()
        self.analyzer = SBOMAnalyzer(self.vuln_db)

    def load_vulnerability_database(self, filepath: str):
        """Load vulnerability database from file."""
        self.vuln_db.load_from_file(filepath)

    def load_remote_vulnerability_database(self):
        """Load Shai-Hulud vulnerability database from remote GitHub source."""
        fetcher = ShaiHuludFetcher()
        json_data = fetcher.fetch()
        self.vuln_db.load_from_shai_hulud_json(json_data)

    def check_application(self, ref: str, debug: bool = False) -> Dict[str, Any]:
        """Check a single application for vulnerabilities."""
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
                "summary": summary
            }
        else:
            # In production mode, catch and handle errors gracefully
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
                    "summary": summary
                }
            except GraphQLError as e:
                return {
                    "ref": ref,
                    "error": f"GraphQL error: {e}",
                    "metadata": {},
                    "sbom_count": 0,
                    "analysis": {"critical": [], "warnings": []},
                    "summary": {"total_critical": 0, "total_warnings": 0, "has_vulnerabilities": False}
                }
            except Exception as e:
                return {
                    "ref": ref,
                    "error": f"Unexpected error: {e}",
                    "metadata": {},
                    "sbom_count": 0,
                    "analysis": {"critical": [], "warnings": []},
                    "summary": {"total_critical": 0, "total_warnings": 0, "has_vulnerabilities": False}
                }

    def check_multiple_applications(self, refs: List[str], debug: bool = False) -> List[Dict[str, Any]]:
        """Check multiple applications for vulnerabilities."""
        results = []
        for ref in refs:
            result = self.check_application(ref, debug)
            results.append(result)
        return results

    def read_refs_from_file(self, filepath: str) -> List[str]:
        """Read application references from a file."""
        try:
            with open(filepath, 'r') as f:
                refs = [line.strip() for line in f if line.strip()]
            return refs
        except FileNotFoundError:
            raise ValueError(f"References file not found: {filepath}")
        except Exception as e:
            raise ValueError(f"Error reading references file: {e}")

    def fetch_all_application_refs(self) -> List[Dict[str, Any]]:
        """Fetch all application data from the NowSecure API.

        Returns:
            List of application dictionaries containing ref, packageKey, and platformType
        """
        try:
            response = self.client.execute_query(APPLICATIONS_QUERY)

            # Extract applications from the response
            applications = response.get('data', {}).get('auto', {}).get('applications', [])

            return applications

        except GraphQLError as e:
            raise ValueError(f"Failed to fetch application references: {e}")
        except Exception as e:
            raise ValueError(f"Unexpected error fetching application references: {e}")