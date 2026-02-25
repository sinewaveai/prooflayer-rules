"""
ProofLayer Runtime Security
============================

Runtime prompt injection firewall for MCP servers.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="prooflayer-runtime",
    version="0.1.0",
    description="Runtime prompt injection firewall for MCP servers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Sinewave AI",
    author_email="divya@sinewave.ai",
    url="https://www.proof-layer.com",
    project_urls={
        "GitHub": "https://github.com/sinewaveai/prooflayer-runtime",
        "Issues": "https://github.com/sinewaveai/agent-security-scanner-mcp/issues",
    },
    packages=find_packages(),
    package_data={
        "prooflayer": [
            "rules/*.yaml",
        ]
    },
    include_package_data=True,
    install_requires=[
        "pyyaml>=6.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
        ]
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="mcp security runtime firewall prompt-injection suse kubernetes",
    license="Proprietary",
)
