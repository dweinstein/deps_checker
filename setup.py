#!/usr/bin/env python3
"""Setup script for NowSecure SBOM Vulnerability Checker."""

from setuptools import setup, find_packages
import os

# Read version from __init__.py
def get_version():
    with open("deps_checker/__init__.py", "r") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().strip('"')
    return "0.0.0"

# Read README for long description
def get_long_description():
    if os.path.exists("README.md"):
        with open("README.md", "r", encoding="utf-8") as f:
            return f.read()
    return ""

setup(
    name="deps-checker",
    version=get_version(),
    author="David Weinstein",
    description="NowSecure SBOM vulnerability checker",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    package_data={
        "deps_checker": ["data/vulnerable.txt"],
    },
    entry_points={
        "console_scripts": [
            "check-sbom=deps_checker.cli:main",
        ],
    },
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="security vulnerability sbom nowsecure dependencies",
    project_urls={
        "Source": "https://github.com/your-org/deps-checker",
        "Documentation": "https://github.com/your-org/deps-checker#readme",
    },
)