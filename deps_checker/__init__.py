"""NowSecure SBOM Vulnerability Checker

A Python tool to fetch and analyze Software Bill of Materials (SBOM) data
from NowSecure's GraphQL API to identify vulnerable dependencies.
"""

__version__ = "1.0.0"
__author__ = "David Weinstein"

# Import main classes for easy access
from .vuln_db import VulnerabilityDatabase
from .sbom_analyzer import SBOMAnalyzer
from .graphql_client import GraphQLClient, GraphQLError

__all__ = [
    "VulnerabilityDatabase",
    "SBOMAnalyzer",
    "GraphQLClient",
    "GraphQLError",
    "__version__",
]