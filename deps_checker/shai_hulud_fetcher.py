"""
Shai-Hulud 2.0 vulnerability database fetcher.
Handles fetching the Shai-Hulud malware package list from GitHub.
"""

import json
import urllib.request
import urllib.error


class ShaiHuludFetcher:
    """Fetches Shai-Hulud 2.0 compromised packages database from GitHub."""

    SHAI_HULUD_URL = "https://raw.githubusercontent.com/gensecaihq/Shai-Hulud-2.0-Detector/refs/heads/main/compromised-packages.json"

    def __init__(self, timeout=30):
        """
        Initialize the Shai-Hulud fetcher.

        Args:
            timeout: Request timeout in seconds (default: 30)
        """
        self.timeout = timeout

    def fetch(self):
        """
        Fetch Shai-Hulud 2.0 vulnerability database from GitHub.

        Returns:
            dict: Parsed JSON data containing vulnerability information

        Raises:
            Exception: If the request fails or JSON is invalid
        """
        try:
            request = urllib.request.Request(
                self.SHAI_HULUD_URL,
                headers={'User-Agent': 'NowSecure-SBOM-Checker/1.0'}
            )

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}: Failed to fetch Shai-Hulud database")

                data = response.read().decode('utf-8')
                return json.loads(data)

        except urllib.error.HTTPError as e:
            raise Exception(f"HTTP error fetching Shai-Hulud database: {e.code} {e.reason}")
        except urllib.error.URLError as e:
            raise Exception(f"Network error fetching Shai-Hulud database: {e.reason}")
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON in Shai-Hulud database: {e}")
        except Exception as e:
            raise Exception(f"Error fetching Shai-Hulud database: {str(e)}")
