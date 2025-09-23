# NowSecure SBOM Vulnerability Checker

A Python tool to fetch and analyze Software Bill of Materials (SBOM) data
from NowSecure's GraphQL API to identify vulnerable dependencies.

## Features

- Query NowSecure GraphQL API for SBOM data
  - Note: Uses latest complete assessment
- Check dependencies against known vulnerable versions
- Support for batch processing multiple applications
- Multiple output formats (text, JSON, CSV)
- No external dependencies (uses Python standard library only)

## Requirements

- Python 3.7+
- NowSecure API key

## Installation

Clone or download the files:
- `check_sbom.py` - Main CLI tool
- `graphql_client.py` - GraphQL client
- `vuln_db.py` - Vulnerability database
- `sbom_analyzer.py` - SBOM analysis logic

Make the script executable:
```bash
chmod +x check_sbom.py
```

## Usage

### Basic Usage

Check a single application:
```bash
python check_sbom.py --ref "uuid-here" --api-key "your-api-key" --vuln-db vulnerable.txt
```

Using environment variable for API key:
```bash
export NS_API_KEY="your-api-key"
python check_sbom.py --ref "uuid-here" --vuln-db vulnerable.txt
```

You can also use the sample environment file as a template:
```bash
cp .env.sample .env
# Edit .env with your actual API key
source .env
python check_sbom.py --ref "uuid-here" --vuln-db vulnerable.txt
```

### Multiple Applications

Check multiple applications at once:
```bash
python check_sbom.py --refs "uuid1" "uuid2" "uuid3" --api-key "your-api-key" --vuln-db vulnerable.txt
```

Read references from a file:
```bash
python check_sbom.py --refs-file app_refs.txt --api-key "your-api-key" --vuln-db vulnerable.txt
```

### Output Formats

JSON output:
```bash
python check_sbom.py --ref "uuid" --api-key "key" --vuln-db vulnerable.txt --format json > results.json
```

CSV output:
```bash
python check_sbom.py --ref "uuid" --api-key "key" --vuln-db vulnerable.txt --format csv > results.csv
```

Verbose text output:
```bash
python check_sbom.py --ref "uuid" --api-key "key" --vuln-db vulnerable.txt --verbose
```

Debug mode (errors propagate for easier debugging):
```bash
python check_sbom.py --ref "uuid" --api-key "key" --vuln-db vulnerable.txt --debug
```

### Vulnerability Database

The `--vuln-db` argument is required and specifies which vulnerability database to use. For the full vulnerability database, use the included `vulnerable.txt` file:
```bash
python check_sbom.py --ref "uuid" --api-key "key" --vuln-db vulnerable.txt
```

You can also provide custom vulnerabilities via JSON or TSV files:
```bash
python check_sbom.py --ref "uuid" --api-key "key" --vuln-db custom_vulns.json
```

**Supported formats:**
- **TSV/TXT**: Tab-separated values with format `package<tab>version(s)`. Supports comma-separated multiple versions.
- **JSON**: Object with package names as keys and arrays of versions as values.

**TSV format example:**
```
package	versions
debug	4.4.2
chalk	5.6.1
supports-color	10.2.1,1.2.3
@art-ws/config-eslint	2.0.4, 2.0.5
```

**JSON format example:**
```json
{
  "package-name": ["1.0.0", "1.0.1"],
  "another-package": ["2.3.4"]
}
```

## Exit Codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities detected or error occurred

## Default Vulnerable Packages

The tool checks for these vulnerable versions by default:

| Package | Vulnerable Version |
|---------|-------------------|
| chalk | 5.6.1 |
| debug | 4.4.2 |
| ansi-styles | 6.2.2 |
| strip-ansi | 7.1.1 |
| color-convert | 3.1.1 |
| wrap-ansi | 9.0.1 |
| ansi-regex | 6.2.1 |
| supports-color | 10.2.1 |

## Output Examples

### Text Output
```
Application Ref: 123e4567-e89b-12d3-a456-426614174000
  Package: com.example.app
  Platform: ios
  Total SBOM Items: 45

  CRITICAL - Exact vulnerable version matches (2):
    • debug v4.4.2
      Known vulnerable versions: 4.4.2
    • chalk v5.6.1
      Known vulnerable versions: 5.6.1

  WARNING - Package name matches (1):
    • ansi-styles v6.2.0
      Known vulnerable versions: 6.2.2
```

### JSON Output Structure
```json
{
  "ref": "uuid",
  "metadata": {
    "package_key": "com.example.app",
    "platform": "ios"
  },
  "sbom_count": 45,
  "analysis": {
    "critical": [...],
    "warnings": [...]
  },
  "summary": {
    "total_critical": 2,
    "total_warnings": 1,
    "has_vulnerabilities": true
  }
}
```

## Integration with CI/CD

The tool returns exit code 1 when vulnerabilities are found, making it suitable for CI/CD pipelines:

```bash
python check_sbom.py --refs-file apps.txt --api-key "$NS_API_KEY" --vuln-db vulnerable.txt --format json > results.json
if [ $? -eq 1 ]; then
    echo "Vulnerabilities found!"
    exit 1
fi
```
