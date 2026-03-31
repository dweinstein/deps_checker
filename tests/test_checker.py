import unittest

from deps_checker.sbom_analyzer import SBOMAnalyzer
from deps_checker.checker import SBOMChecker
from deps_checker.vuln_db import VulnerabilityDatabase


class TestBundledVulnerabilityDatabase(unittest.TestCase):
    def test_bundled_database_contains_axios_supply_chain_entries(self):
        vuln_db = VulnerabilityDatabase()
        vuln_db.load_from_file("deps_checker/data/vulnerable.txt")

        self.assertTrue(vuln_db.is_vulnerable_exact("axios", "1.14.1"))
        self.assertTrue(vuln_db.is_vulnerable_exact("axios", "0.30.4"))
        self.assertTrue(vuln_db.is_vulnerable_exact("plain-crypto-js", "4.2.1"))


class TestRemoteDatabaseMerge(unittest.TestCase):
    def test_remote_load_merges_bundled_entries(self):
        checker = SBOMChecker(api_key="test-key", endpoint="https://example.invalid/graphql")

        class FakeFetcher:
            def fetch(self):
                return {
                    "packages": [
                        {"name": "remote-only-package", "affectedVersions": ["*"]},
                    ]
                }

        from deps_checker import checker as checker_module

        original_fetcher = checker_module.ShaiHuludFetcher
        checker_module.ShaiHuludFetcher = FakeFetcher
        try:
            checker.load_remote_vulnerability_database()
        finally:
            checker_module.ShaiHuludFetcher = original_fetcher

        self.assertTrue(checker.vuln_db.is_vulnerable_exact("remote-only-package", "9.9.9"))
        self.assertTrue(checker.vuln_db.is_vulnerable_exact("axios", "1.14.1"))
        self.assertTrue(checker.vuln_db.is_vulnerable_exact("axios", "0.30.4"))
        self.assertTrue(checker.vuln_db.is_vulnerable_exact("plain-crypto-js", "4.2.1"))


class TestAxiosDetection(unittest.TestCase):
    def test_analyzer_flags_axios_and_plain_crypto_js_as_critical(self):
        vuln_db = VulnerabilityDatabase()
        vuln_db.load_from_file("deps_checker/data/vulnerable.txt")

        sbom_items = [
            {"name": "axios", "version": "1.14.1", "source": "npm"},
            {"name": "axios", "version": "0.30.4", "source": "npm"},
            {"name": "plain-crypto-js", "version": "4.2.1", "source": "npm"},
            {"name": "axios", "version": "1.14.0", "source": "npm"},
        ]

        analysis = SBOMAnalyzer(vuln_db)
        results = analysis.analyze_sbom(sbom_items)

        critical_matches = {(item["name"], item["version"]) for item in results["critical"]}
        warning_matches = {(item["name"], item["version"]) for item in results["warnings"]}

        self.assertEqual(
            critical_matches,
            {
                ("axios", "1.14.1"),
                ("axios", "0.30.4"),
                ("plain-crypto-js", "4.2.1"),
            },
        )
        self.assertEqual(warning_matches, {("axios", "1.14.0")})


if __name__ == "__main__":
    unittest.main()
