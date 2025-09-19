#!/usr/bin/env python3
"""
Security Assessment Platform using Strands (Runs Locally!)
Strands + Bright Data MCP + NodeZero MCP
"""

from strands_agents import Agent, Tool, RunContext
from mcp import Client as MCPClient
from typing import Dict, List, Any
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# EXTERNAL RECONNAISSANCE AGENT (with Bright Data MCP)
# ============================================================================

class ExternalReconAgent:
    """External reconnaissance using Bright Data MCP"""

    def __init__(self):
        # Connect to Bright Data MCP
        self.brightdata = MCPClient("brightdata")

        # Define tools for Strands agent
        self.tools = [
            Tool(
                name="osint_search",
                description="Search for exposed data across the internet",
                func=self.osint_search
            ),
            Tool(
                name="subdomain_enum",
                description="Enumerate subdomains with stealth",
                func=self.subdomain_enum
            ),
            Tool(
                name="credential_hunting",
                description="Hunt for leaked credentials",
                func=self.credential_hunting
            )
        ]

        # Create Strands agent
        self.agent = Agent(
            name="External Recon Agent",
            model="gpt-4",  # or use local: "ollama/llama2"
            tools=self.tools,
            prompt="""You are an external reconnaissance specialist.
Your goal is to discover the attack surface of the target using Bright Data's
massive proxy network and search capabilities. Focus on:
1. Finding leaked credentials and API keys
2. Discovering exposed services and subdomains
3. Identifying technology stack and misconfigurations
Always use stealth techniques to avoid detection."""
        )

    async def osint_search(self, target: str) -> Dict:
        """OSINT collection at scale using Bright Data"""

        results = await self.brightdata.call({
            "tool": "search_api",
            "params": {
                "queries": [
                    f'"{target}" "api_key" OR "api_token"',
                    f'site:pastebin.com "{target}"',
                    f'site:github.com "{target}" filename:.env',
                    f'site:reddit.com "{target}" breach',
                    f'filetype:sql "{target}"'
                ],
                "use_residential_proxies": True,
                "parallel_requests": 50
            }
        })

        return {
            "leaked_secrets": self.extract_secrets(results),
            "exposed_files": self.extract_files(results),
            "breach_mentions": self.extract_breaches(results)
        }

    async def subdomain_enum(self, target: str) -> List[str]:
        """Enumerate subdomains without getting blocked"""

        results = await self.brightdata.call({
            "tool": "dns_enumeration",
            "params": {
                "domain": target,
                "techniques": ["ct_logs", "search_engines", "bruteforce"],
                "wordlist": "large",
                "rotate_ips": True
            }
        })

        return results.get("subdomains", [])

    async def credential_hunting(self, target: str) -> Dict:
        """Hunt for credentials across multiple sources"""

        results = await self.brightdata.call({
            "tool": "credential_search",
            "params": {
                "target": target,
                "sources": ["github", "gitlab", "pastebin", "darkweb"],
                "patterns": ["password", "api_key", "token", "secret"],
                "use_tor_exit_nodes": True
            }
        })

        return results

    async def execute(self, target: str) -> Dict:
        """Execute reconnaissance mission"""

        context = RunContext(
            inputs={"target": target},
            metadata={"phase": "external_recon"}
        )

        result = await self.agent.run(
            f"Perform comprehensive external reconnaissance on {target}",
            context=context
        )

        return result

    def extract_secrets(self, results):
        # Parse results for secrets
        return [r for r in results.get("results", []) if "api" in r.lower()]

    def extract_files(self, results):
        # Parse results for files
        return [r for r in results.get("results", []) if "filetype" in r]

    def extract_breaches(self, results):
        # Parse results for breach mentions
        return [r for r in results.get("results", []) if "breach" in r.lower()]


# ============================================================================
# INTERNAL PENETRATION AGENT (with NodeZero MCP)
# ============================================================================

class InternalPentestAgent:
    """Internal penetration testing using NodeZero MCP"""

    def __init__(self):
        # Connect to NodeZero MCP
        self.nodezero = MCPClient("nodezero")

        # Define tools for Strands agent
        self.tools = [
            Tool(
                name="network_scan",
                description="Scan internal network segments",
                func=self.network_scan
            ),
            Tool(
                name="exploit_vulnerability",
                description="Safely exploit discovered vulnerabilities",
                func=self.exploit_vulnerability
            ),
            Tool(
                name="lateral_movement",
                description="Move laterally through network",
                func=self.lateral_movement
            )
        ]

        # Create Strands agent
        self.agent = Agent(
            name="Internal Pentest Agent",
            model="gpt-4",
            tools=self.tools,
            prompt="""You are an internal penetration tester.
Using NodeZero's autonomous pentesting capabilities, you will:
1. Map the internal network
2. Identify and exploit vulnerabilities
3. Demonstrate lateral movement
4. Find paths to critical assets
Always maintain safety controls and document impact."""
        )

    async def network_scan(self, entry_point: Dict) -> Dict:
        """Scan internal network from entry point"""

        results = await self.nodezero.call({
            "tool": "network_discovery",
            "params": {
                "entry_point": entry_point,
                "scan_type": "comprehensive",
                "targets": ["192.168.0.0/16", "10.0.0.0/8"]
            }
        })

        return results

    async def exploit_vulnerability(self, target: str, vuln: str) -> Dict:
        """Safely exploit vulnerability"""

        results = await self.nodezero.call({
            "tool": "exploit",
            "params": {
                "target": target,
                "vulnerability": vuln,
                "safe_mode": True,
                "capture_proof": True
            }
        })

        return results

    async def lateral_movement(self, from_host: str, to_host: str) -> Dict:
        """Attempt lateral movement"""

        results = await self.nodezero.call({
            "tool": "lateral_movement",
            "params": {
                "source": from_host,
                "target": to_host,
                "techniques": ["all"],
                "safe_mode": True
            }
        })

        return results

    async def execute(self, entry_point: Dict, external_intel: Dict) -> Dict:
        """Execute internal penetration test"""

        context = RunContext(
            inputs={
                "entry_point": entry_point,
                "external_intel": external_intel
            },
            metadata={"phase": "internal_pentest"}
        )

        result = await self.agent.run(
            f"Perform internal penetration test from {entry_point}",
            context=context
        )

        return result


# ============================================================================
# SECURITY ORCHESTRATOR (Strands Multi-Agent Coordination)
# ============================================================================

class SecurityOrchestrator:
    """Orchestrates multiple agents for complete security assessment"""

    def __init__(self):
        # Initialize specialized agents
        self.external_agent = ExternalReconAgent()
        self.internal_agent = InternalPentestAgent()

        # Create orchestrator agent
        self.orchestrator = Agent(
            name="Security Orchestrator",
            model="gpt-4",
            tools=[
                Tool(
                    name="external_recon",
                    description="Run external reconnaissance",
                    func=self.run_external_recon
                ),
                Tool(
                    name="internal_pentest",
                    description="Run internal penetration test",
                    func=self.run_internal_pentest
                ),
                Tool(
                    name="analyze_attack_chain",
                    description="Analyze complete attack chain",
                    func=self.analyze_attack_chain
                )
            ],
            prompt="""You are the master security orchestrator.
Coordinate external reconnaissance and internal penetration testing to:
1. Discover external attack surface
2. Identify entry points
3. Demonstrate internal compromise paths
4. Show complete attack chains from external to internal
Provide actionable recommendations based on findings."""
        )

    async def run_external_recon(self, target: str) -> Dict:
        """Execute external reconnaissance"""
        return await self.external_agent.execute(target)

    async def run_internal_pentest(self, entry_point: Dict, intel: Dict) -> Dict:
        """Execute internal penetration test"""
        return await self.internal_agent.execute(entry_point, intel)

    async def analyze_attack_chain(self, external: Dict, internal: Dict) -> Dict:
        """Analyze complete attack chain"""

        attack_chains = []

        # Link external findings to internal compromises
        for entry in external.get("entry_points", []):
            for compromise in internal.get("compromised_systems", []):
                if self.can_link(entry, compromise):
                    attack_chains.append({
                        "entry": entry,
                        "compromise": compromise,
                        "impact": self.assess_impact(compromise)
                    })

        return {
            "attack_chains": attack_chains,
            "critical_path": max(attack_chains, key=lambda x: x["impact"]) if attack_chains else None
        }

    def can_link(self, entry, compromise):
        """Check if entry point can lead to compromise"""
        # Logic to link external to internal
        return True  # Simplified

    def assess_impact(self, compromise):
        """Assess business impact"""
        if "admin" in str(compromise).lower():
            return 10  # Critical
        elif "database" in str(compromise).lower():
            return 8  # High
        return 5  # Medium

    async def assess(self, target: str) -> Dict:
        """Run complete security assessment"""

        context = RunContext(
            inputs={"target": target},
            metadata={"assessment_type": "comprehensive"}
        )

        result = await self.orchestrator.run(
            f"Perform comprehensive security assessment of {target}. "
            f"Start with external reconnaissance, then use findings for internal testing.",
            context=context
        )

        return result


# ============================================================================
# MAIN EXECUTION
# ============================================================================

async def main():
    """Run security assessment with Strands"""

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║      STRANDS SECURITY ASSESSMENT PLATFORM                   ║
    ║      Running Locally with Full Agent Orchestration          ║
    ║      Powered by: Strands + Bright Data + NodeZero          ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    # Get target
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    print(f"\n[*] Target: {target}")
    print("[*] Initializing agents...")

    # Create orchestrator
    orchestrator = SecurityOrchestrator()

    # Connect MCP servers
    await orchestrator.external_agent.brightdata.connect()
    await orchestrator.internal_agent.nodezero.connect()

    print("[*] Starting assessment...\n")

    # Run assessment
    results = await orchestrator.assess(target)

    # Display results
    print("\n" + "="*60)
    print(" ASSESSMENT RESULTS")
    print("="*60)

    print(f"\nTarget: {target}")
    print(f"Risk Level: {results.get('risk_level', 'Unknown')}")

    if results.get('attack_chains'):
        print(f"\nAttack Chains Found: {len(results['attack_chains'])}")
        for i, chain in enumerate(results['attack_chains'][:3], 1):
            print(f"\n  Chain {i}:")
            print(f"    Entry: {chain['entry']}")
            print(f"    Impact: {chain['impact']}")

    print("\n" + "="*60)

    # Save results
    import json
    with open(f"strands_assessment_{target.replace('.', '_')}.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nResults saved to: strands_assessment_{target.replace('.', '_')}.json")


if __name__ == "__main__":
    asyncio.run(main())