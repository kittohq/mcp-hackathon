"""
External Reconnaissance Agent using Bright Data MCP
Handles all external attack surface discovery
"""

from airia import Agent, Task, tool
from mcp import Client as MCPClient
from typing import Dict, List, Any
import asyncio
import json

class ExternalReconAgent(Agent):
    """Agent specialized in external reconnaissance using Bright Data MCP"""

    def __init__(self):
        super().__init__(
            name="external_recon_agent",
            description="Discovers external attack surface using OSINT and web scanning",
            model="gpt-4"  # or claude-3
        )
        self.brightdata_mcp = None
        self.discovered_assets = []

    async def connect_mcp(self):
        """Connect to Bright Data MCP server"""
        self.brightdata_mcp = MCPClient("brightdata")
        await self.brightdata_mcp.connect()

        # Auto-discover available tools
        self.available_tools = await self.brightdata_mcp.list_tools()
        print(f"[External Recon] Connected to Bright Data MCP with {len(self.available_tools)} tools")

    @tool
    async def scan_external_surface(self, target: str) -> Dict[str, Any]:
        """Scan external attack surface of target"""
        results = {
            "target": target,
            "exposed_services": [],
            "leaked_credentials": [],
            "misconfigurations": [],
            "vulnerable_endpoints": []
        }

        # Web scraping for exposed services
        web_scan = await self.brightdata_mcp.call({
            "tool": "web_scraper",
            "params": {
                "url": f"https://{target}",
                "extract": ["headers", "forms", "scripts", "comments"]
            }
        })

        # Search for leaked credentials
        cred_search = await self.brightdata_mcp.call({
            "tool": "search_api",
            "params": {
                "queries": [
                    f"site:github.com \"{target}\" password",
                    f"site:pastebin.com \"{target}\"",
                    f"filetype:sql \"{target}\"",
                    f"filetype:env \"{target}\""
                ]
            }
        })

        # Check for exposed cloud storage
        cloud_scan = await self.brightdata_mcp.call({
            "tool": "web_scraper",
            "params": {
                "urls": [
                    f"https://{target}.s3.amazonaws.com",
                    f"https://storage.googleapis.com/{target}",
                    f"https://{target}.blob.core.windows.net"
                ]
            }
        })

        # Parse results
        if web_scan.get("headers"):
            results["misconfigurations"] = self.analyze_headers(web_scan["headers"])

        if cred_search.get("results"):
            results["leaked_credentials"] = self.extract_credentials(cred_search["results"])

        if cloud_scan.get("accessible"):
            results["exposed_services"].extend(cloud_scan["accessible"])

        self.discovered_assets = results
        return results

    @tool
    async def find_subdomains(self, target: str) -> List[str]:
        """Discover subdomains for target"""
        subdomain_search = await self.brightdata_mcp.call({
            "tool": "search_api",
            "params": {
                "query": f"site:*.{target}",
                "limit": 100
            }
        })

        subdomains = self.parse_subdomains(subdomain_search)
        return subdomains

    @tool
    async def check_security_headers(self, target: str) -> Dict[str, bool]:
        """Check security headers on target"""
        headers_check = await self.brightdata_mcp.call({
            "tool": "web_scraper",
            "params": {
                "url": f"https://{target}",
                "extract": ["headers"]
            }
        })

        security_headers = {
            "HSTS": "Strict-Transport-Security" in headers_check.get("headers", {}),
            "CSP": "Content-Security-Policy" in headers_check.get("headers", {}),
            "X-Frame-Options": "X-Frame-Options" in headers_check.get("headers", {}),
            "X-Content-Type-Options": "X-Content-Type-Options" in headers_check.get("headers", {})
        }

        return security_headers

    @Task(description="Perform comprehensive external reconnaissance")
    async def reconnaissance(self, target: str) -> Dict[str, Any]:
        """Main reconnaissance task"""
        print(f"[External Recon] Starting reconnaissance on {target}")

        # Run all scans in parallel
        results = await asyncio.gather(
            self.scan_external_surface(target),
            self.find_subdomains(target),
            self.check_security_headers(target),
            return_exceptions=True
        )

        # Compile findings
        findings = {
            "surface_scan": results[0] if not isinstance(results[0], Exception) else {},
            "subdomains": results[1] if not isinstance(results[1], Exception) else [],
            "security_headers": results[2] if not isinstance(results[2], Exception) else {}
        }

        # Identify entry points for internal testing
        entry_points = self.identify_entry_points(findings)
        findings["potential_entry_points"] = entry_points

        print(f"[External Recon] Found {len(entry_points)} potential entry points")
        return findings

    def analyze_headers(self, headers: Dict) -> List[str]:
        """Analyze headers for misconfigurations"""
        issues = []
        if not headers.get("X-Frame-Options"):
            issues.append("Missing X-Frame-Options (Clickjacking risk)")
        if not headers.get("Content-Security-Policy"):
            issues.append("Missing CSP (XSS risk)")
        if headers.get("Server"):
            issues.append(f"Server header exposed: {headers['Server']}")
        return issues

    def extract_credentials(self, search_results: List) -> List[Dict]:
        """Extract potential credentials from search results"""
        credentials = []
        for result in search_results:
            if "password" in result.lower() or "api_key" in result.lower():
                credentials.append({
                    "source": result.get("url", "unknown"),
                    "type": "potential_credential",
                    "content": result.get("snippet", "")
                })
        return credentials

    def parse_subdomains(self, search_results: Dict) -> List[str]:
        """Parse subdomains from search results"""
        subdomains = set()
        for result in search_results.get("results", []):
            url = result.get("url", "")
            if "://" in url:
                domain = url.split("://")[1].split("/")[0]
                subdomains.add(domain)
        return list(subdomains)

    def identify_entry_points(self, findings: Dict) -> List[Dict]:
        """Identify potential entry points from reconnaissance"""
        entry_points = []

        # Check for leaked credentials
        if findings["surface_scan"].get("leaked_credentials"):
            for cred in findings["surface_scan"]["leaked_credentials"]:
                entry_points.append({
                    "type": "credential",
                    "risk": "high",
                    "details": cred
                })

        # Check for vulnerable services
        for service in findings["surface_scan"].get("exposed_services", []):
            entry_points.append({
                "type": "exposed_service",
                "risk": "medium",
                "details": service
            })

        # Check for misconfigurations
        for issue in findings["surface_scan"].get("misconfigurations", []):
            if "XSS" in issue or "Clickjacking" in issue:
                entry_points.append({
                    "type": "misconfiguration",
                    "risk": "medium",
                    "details": issue
                })

        return entry_points