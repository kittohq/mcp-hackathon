#!/usr/bin/env python3
"""
Main entry point for the AI Security Assessment Platform
Demonstrates Airia SDK + Bright Data MCP + NodeZero MCP integration
"""

import asyncio
import sys
import json
from datetime import datetime
import argparse
from typing import Optional

# Import our agents
sys.path.append('src/agents')
from security_orchestrator import SecurityOrchestrator


async def run_security_assessment(target: str, assessment_type: str = "full"):
    """Run a comprehensive security assessment on the target"""

    print("\n" + "="*70)
    print(" AI SECURITY ASSESSMENT PLATFORM")
    print(" Powered by: Airia + Bright Data + NodeZero")
    print("="*70 + "\n")

    # Initialize orchestrator
    orchestrator = SecurityOrchestrator()

    try:
        # Initialize all agents and connections
        await orchestrator.initialize()

        # Execute assessment
        report = await orchestrator.assess_security(target, assessment_type)

        # Save report
        filename = f"report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n[SUCCESS] Report saved to: {filename}")

        # Print summary
        print_summary(report)

        return report

    except Exception as e:
        print(f"\n[ERROR] Assessment failed: {str(e)}")
        return None


def print_summary(report: dict):
    """Print a summary of the assessment report"""

    print("\n" + "="*70)
    print(" ASSESSMENT SUMMARY")
    print("="*70)

    summary = report.get("executive_summary", {})

    print(f"\nTarget: {report.get('target')}")
    print(f"Assessment ID: {report.get('assessment_id')}")
    print(f"Risk Level: {summary.get('risk_level')}")
    print(f"Risk Score: {summary.get('risk_score')}/100")

    print("\nTop Risks:")
    for i, risk in enumerate(summary.get("top_risks", []), 1):
        print(f"  {i}. {risk}")

    print("\nKey Findings:")
    for finding in summary.get("key_findings", []):
        print(f"  • {finding}")

    # Print attack chains if found
    attack_analysis = report.get("attack_chain_analysis", {})
    chains = attack_analysis.get("attack_chains", [])
    if chains:
        print(f"\nAttack Chains Discovered: {len(chains)}")
        critical_path = attack_analysis.get("most_critical_path", {})
        if critical_path:
            print("\nMost Critical Attack Path:")
            for step in critical_path.get("attack_path", []):
                print(f"  → {step}")

    # Print recommendations
    recommendations = report.get("recommendations", {})
    immediate = recommendations.get("immediate", [])
    if immediate:
        print("\nImmediate Actions Required:")
        for rec in immediate:
            print(f"  ! {rec}")

    print("\n" + "="*70)


async def demo_mode():
    """Run a demo with a sample target"""

    print("\n" + "*"*70)
    print(" DEMO MODE - Simulating assessment on example.com")
    print("*"*70 + "\n")

    # Create mock responses for demo
    class DemoOrchestrator(SecurityOrchestrator):
        async def initialize(self):
            print("[Demo] Initializing agents (simulated)...")
            await asyncio.sleep(1)
            print("[Demo] Agents connected to MCP servers (simulated)")

        async def assess_security(self, target: str, assessment_type: str = "full"):
            print(f"[Demo] Starting security assessment on {target}")

            # Simulate external reconnaissance
            print("\n[Demo] Phase 1: External Reconnaissance")
            await asyncio.sleep(2)
            print("  ✓ Found exposed admin panel at /admin")
            print("  ✓ Discovered leaked API key on GitHub")
            print("  ✓ Missing security headers detected")

            # Simulate internal penetration
            print("\n[Demo] Phase 2: Internal Penetration Testing")
            await asyncio.sleep(2)
            print("  ✓ Used API key for initial access")
            print("  ✓ Discovered 3 unpatched systems")
            print("  ✓ Achieved privilege escalation on database server")

            # Simulate attack chain analysis
            print("\n[Demo] Phase 3: Attack Chain Analysis")
            await asyncio.sleep(1)
            print("  ✓ Identified complete kill chain")
            print("  ✓ Path: GitHub leak → API access → Database compromise")

            return {
                "assessment_id": f"demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "executive_summary": {
                    "risk_level": "HIGH",
                    "risk_score": 72,
                    "top_risks": [
                        "Leaked API credentials on GitHub",
                        "Unpatched critical vulnerabilities",
                        "Weak network segmentation"
                    ],
                    "key_findings": [
                        "Found 3 potential entry points from external scan",
                        "Successfully compromised 2 internal systems",
                        "Identified 1 complete attack chain"
                    ]
                },
                "attack_chain_analysis": {
                    "attack_chains": [{
                        "entry_vector": {"type": "credential", "risk": "high"},
                        "attack_path": [
                            "External: Leaked API key found on GitHub",
                            "Use API key for authentication",
                            "Access internal API server",
                            "Exploit unpatched vulnerability",
                            "Escalate to database admin"
                        ],
                        "impact": "critical"
                    }],
                    "most_critical_path": {
                        "attack_path": [
                            "GitHub leak",
                            "API authentication",
                            "Internal access",
                            "Database compromise"
                        ],
                        "impact": "critical"
                    }
                },
                "recommendations": {
                    "immediate": [
                        "Rotate all API keys immediately",
                        "Patch critical vulnerabilities",
                        "Enable MFA on all admin accounts"
                    ]
                }
            }

    orchestrator = DemoOrchestrator()
    report = await orchestrator.assess_security("example.com")
    print_summary(report)


async def main():
    """Main entry point"""

    parser = argparse.ArgumentParser(
        description="AI Security Assessment Platform - Airia + Bright Data + NodeZero"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target domain to assess (e.g., example.com)"
    )
    parser.add_argument(
        "--type",
        choices=["full", "external", "internal"],
        default="full",
        help="Type of assessment to perform"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode with simulated results"
    )

    args = parser.parse_args()

    if args.demo or not args.target:
        # Run demo mode
        await demo_mode()
    else:
        # Run real assessment
        await run_security_assessment(args.target, args.type)


if __name__ == "__main__":
    asyncio.run(main())