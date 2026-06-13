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
    name="prooflayer-rules",
    version="0.1.0",
    description="Open-source runtime security rules engine for MCP servers and AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Sinewave AI",
    author_email="founders@sinewaveai.com",
    url="https://www.proof-layer.com",
    project_urls={
        "GitHub": "https://github.com/sinewaveai/prooflayer-rules",
        "Issues": "https://github.com/sinewaveai/prooflayer-rules/issues",
    },
    packages=find_packages(),
    package_data={
        "prooflayer": [
            "rules/*.yaml",
            "compliance/frameworks/*.yaml",
        ]
    },
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "prooflayer=prooflayer.cli:main",
        ],
    },
    install_requires=[
        "pyyaml>=6.0.0",
        "httpx>=0.27.0",
    ],
    extras_require={
        "mcp": [
            "mcp>=1.0.0",
        ],
        "langgraph": [
            "langgraph>=0.2.0,<1.0.0",
            "langchain-core>=0.3.0",
        ],
        "evals": [
            "docker>=7.0.0",
            "pyyaml>=6.0.0",
        ],
        "compliance": [
            "jinja2>=3.1.0",
            "weasyprint>=60.0",
        ],
        "all": [
            "langgraph>=0.2.0,<1.0.0",
            "langchain-core>=0.3.0",
            "docker>=7.0.0",
            "pyyaml>=6.0.0",
            "jinja2>=3.1.0",
            "weasyprint>=60.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-timeout>=2.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="mcp security runtime firewall prompt-injection ai-agents ai-security",
    license="Apache-2.0",
)
