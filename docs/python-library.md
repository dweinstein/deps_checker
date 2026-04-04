# Python Library Usage

You can use the package programmatically after installation.

```python
from deps_checker.checker import SBOMChecker
from deps_checker.vuln_db import VulnerabilityDatabase

checker = SBOMChecker(api_key="your-api-key")

# Remote Shai-Hulud data plus bundled curated entries
checker.load_remote_vulnerability_database()

# Or load a local file instead
# checker.load_vulnerability_database("deps_checker/data/vulnerable.txt")

result = checker.check_application("uuid-here")
print(result["summary"]["has_vulnerabilities"])

vuln_db = VulnerabilityDatabase()
vuln_db.load_from_file("deps_checker/data/vulnerable.txt")
print(vuln_db.is_vulnerable_exact("chalk", "5.6.1"))
```

Relevant entry points:

- `SBOMChecker.load_remote_vulnerability_database()`
- `SBOMChecker.load_vulnerability_database(path)`
- `SBOMChecker.check_application(ref)`
- `SBOMChecker.check_multiple_applications(refs)`
- `SBOMChecker.fetch_all_application_refs()`
- `VulnerabilityDatabase.load_from_file(path)`
