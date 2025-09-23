import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional


class GraphQLClient:
    def __init__(self, endpoint: str, api_key: Optional[str] = None):
        self.endpoint = endpoint
        self.api_key = api_key

    def execute_query(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'

        payload = {
            'query': query,
            'variables': variables or {}
        }

        data = json.dumps(payload).encode('utf-8')
        request = urllib.request.Request(
            self.endpoint,
            data=data,
            headers=headers,
            method='POST'
        )

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_data = response.read().decode('utf-8')
                result = json.loads(response_data)

                if 'errors' in result:
                    # Include the full error details for debugging
                    error_msg = json.dumps(result['errors'], indent=2)
                    raise GraphQLError(f"GraphQL errors:\n{error_msg}")

                return result

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            # Try to parse as JSON for better error messages
            try:
                error_json = json.loads(error_body)
                error_body = json.dumps(error_json, indent=2)
            except:
                pass
            raise GraphQLError(f"HTTP {e.code}:\n{error_body}")
        except urllib.error.URLError as e:
            raise GraphQLError(f"Network error: {str(e)}")
        except json.JSONDecodeError as e:
            raise GraphQLError(f"Invalid JSON response: {str(e)}\nResponse: {response_data[:500]}...")


class GraphQLError(Exception):
    pass