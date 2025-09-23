from typing import Dict, List, Set, Tuple

VULNERABLE_PACKAGES = { }

class VulnerabilityDatabase:
    def __init__(self, vulnerabilities: Dict[str, List[str]] = None):
        self.vulnerabilities = vulnerabilities or VULNERABLE_PACKAGES

    def is_vulnerable_exact(self, package_name: str, version: str) -> bool:
        if package_name not in self.vulnerabilities:
            return False
        return version in self.vulnerabilities[package_name]

    def has_vulnerable_package(self, package_name: str) -> bool:
        return package_name in self.vulnerabilities

    def get_vulnerable_versions(self, package_name: str) -> List[str]:
        return self.vulnerabilities.get(package_name, [])

    def add_vulnerability(self, package_name: str, version: str):
        if package_name not in self.vulnerabilities:
            self.vulnerabilities[package_name] = []
        if version not in self.vulnerabilities[package_name]:
            self.vulnerabilities[package_name].append(version)

    def load_from_file(self, filepath: str):
        import json
        import os

        try:
            file_ext = os.path.splitext(filepath)[1].lower()

            if file_ext == '.json':
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    self.vulnerabilities.update(data)
            elif file_ext == '.txt' or file_ext == '.tsv':
                self._load_from_tsv(filepath)
            else:
                raise ValueError(f"Unsupported file format: {file_ext}. Supported formats: .json, .txt, .tsv")

        except Exception as e:
            raise ValueError(f"Failed to load vulnerabilities from {filepath}: {e}")

    def _load_from_tsv(self, filepath: str):
        """Load vulnerabilities from a TSV file with format: package<tab>version(s)
        Supports both single versions and comma-separated multiple versions"""
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Skip header if present
        start_idx = 0
        if lines and 'package' in lines[0].lower() and 'version' in lines[0].lower():
            start_idx = 1

        for line_num, line in enumerate(lines[start_idx:], start=start_idx + 1):
            line = line.strip()
            if not line:
                continue

            parts = line.split('\t')
            if len(parts) != 2:
                raise ValueError(f"Invalid TSV format at line {line_num}: expected 2 columns (package<tab>version), got {len(parts)}")

            package_name, versions_str = parts[0].strip(), parts[1].strip()
            if package_name and versions_str:
                # Split on comma and handle both single and multiple versions
                versions = [v.strip() for v in versions_str.split(',') if v.strip()]
                for version in versions:
                    self.add_vulnerability(package_name, version)

    def get_all_vulnerable_packages(self) -> Set[str]:
        return set(self.vulnerabilities.keys())

    def dump_database(self) -> Dict[str, List[str]]:
        """Return the entire vulnerability database for debugging."""
        return dict(self.vulnerabilities)

    def dump_to_stderr(self):
        """Dump the vulnerability database to stderr for debugging."""
        import json
        import sys
        print("\n=== DEBUG: Vulnerability Database ===", file=sys.stderr)
        print(f"Total vulnerable packages: {len(self.vulnerabilities)}", file=sys.stderr)
        print(f"Total vulnerable versions: {sum(len(v) for v in self.vulnerabilities.values())}", file=sys.stderr)
        print("\nDatabase contents:", file=sys.stderr)
        print(json.dumps(self.vulnerabilities, indent=2, sort_keys=True), file=sys.stderr)
        print("=== END Vulnerability Database ===\n", file=sys.stderr)
