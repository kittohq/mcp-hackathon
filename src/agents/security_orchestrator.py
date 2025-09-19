"""
Security Orchestrator Agent - Coordinates external and internal security testing
Uses Airia SDK to manage collaboration between Bright Data and NodeZero agents
"""

from airia import Agent, Task, tool, Workflow
from typing import Dict, List, Any, Optional
import asyncio
import json
from datetime import datetime

from external_recon_agent import ExternalReconAgent
from internal_pentest_agent import InternalPentestAgent

class SecurityOrchestrator(Agent):
    """Master orchestrator that coordinates all security testing agents"""

    def __init__(self):
        super().__init__(
            name="security_orchestrator",
            description="Orchestrates comprehensive security assessments combining external and internal testing",
            model="gpt-4"
        )

        # Initialize specialized agents
        self.external_agent = ExternalReconAgent()
        self.internal_agent = InternalPentestAgent()

        # Track assessment state
        self.assessment_id = None
        self.target = None
        self.findings = {
            "external": {},
            "internal": {},
            "combined": {}
        }

    async def initialize(self):
        """Initialize all agents and MCP connections"""
        print("[Orchestrator] Initializing security assessment platform...")

        # Connect agents to their MCP servers
        await asyncio.gather(
            self.external_agent.connect_mcp(),
            self.internal_agent.connect_mcp()
        )

        print("[Orchestrator] All agents initialized and connected")

    @tool
    async def analyze_attack_chain(self, external_findings: Dict, internal_findings: Dict) -> Dict[str, Any]:
        """Analyze how external vulnerabilities lead to internal compromise"""

        attack_chains = []

        # Link external entry points to internal compromises
        for entry in external_findings.get("potential_entry_points", []):
            # Find internal systems compromised through this entry
            for system in internal_findings.get("exploited_systems", []):
                if self.can_link_attack(entry, system):
                    attack_chains.append({
                        "entry_vector": entry,
                        "initial_compromise": system,
                        "attack_path": self.trace_attack_path(entry, system, internal_findings),
                        "impact": self.calculate_impact(system, internal_findings)
                    })

        return {
            "attack_chains": attack_chains,
            "most_critical_path": self.identify_critical_path(attack_chains),
            "recommendations": self.generate_recommendations(attack_chains)
        }

    @tool
    async def generate_risk_score(self, findings: Dict) -> Dict[str, Any]:
        """Generate comprehensive risk score based on all findings"""

        risk_factors = {
            "external_exposure": self.calculate_external_risk(findings["external"]),
            "internal_vulnerability": self.calculate_internal_risk(findings["internal"]),
            "attack_chain_feasibility": self.calculate_chain_risk(findings["combined"]),
            "business_impact": self.calculate_business_impact(findings)
        }

        # Weighted risk calculation
        overall_risk = (
            risk_factors["external_exposure"] * 0.25 +
            risk_factors["internal_vulnerability"] * 0.35 +
            risk_factors["attack_chain_feasibility"] * 0.30 +
            risk_factors["business_impact"] * 0.10
        )

        return {
            "overall_risk_score": round(overall_risk, 2),
            "risk_level": self.get_risk_level(overall_risk),
            "risk_factors": risk_factors,
            "top_risks": self.identify_top_risks(findings)
        }

    @Task(description="Execute comprehensive security assessment")
    async def assess_security(self, target: str, assessment_type: str = "full") -> Dict[str, Any]:
        """Main orchestration task for security assessment"""

        self.target = target
        self.assessment_id = f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        print(f"\n{'='*60}")
        print(f"[Orchestrator] Starting {assessment_type} security assessment")
        print(f"[Orchestrator] Target: {target}")
        print(f"[Orchestrator] Assessment ID: {self.assessment_id}")
        print(f"{'='*60}\n")

        # Phase 1: External Reconnaissance
        print("\n[Phase 1] EXTERNAL RECONNAISSANCE")
        print("-" * 40)
        external_findings = await self.external_agent.reconnaissance(target)
        self.findings["external"] = external_findings

        # Analyze external results
        entry_points = external_findings.get("potential_entry_points", [])
        print(f"[Orchestrator] External scan complete: {len(entry_points)} entry points found")

        # Decision point: Continue to internal testing?
        if not entry_points:
            print("[Orchestrator] No entry points found. Skipping internal testing.")
            return self.compile_external_only_report()

        # Phase 2: Internal Penetration Testing
        print("\n[Phase 2] INTERNAL PENETRATION TESTING")
        print("-" * 40)

        # Select best entry point for internal testing
        best_entry = self.select_best_entry_point(entry_points)
        print(f"[Orchestrator] Selected entry point: {best_entry['type']}")

        # Execute internal pentest
        internal_findings = await self.internal_agent.penetration_test(
            best_entry,
            external_findings
        )
        self.findings["internal"] = internal_findings

        # Phase 3: Attack Chain Analysis
        print("\n[Phase 3] ATTACK CHAIN ANALYSIS")
        print("-" * 40)

        attack_analysis = await self.analyze_attack_chain(
            external_findings,
            internal_findings
        )
        self.findings["combined"] = attack_analysis

        # Phase 4: Risk Assessment
        print("\n[Phase 4] RISK ASSESSMENT")
        print("-" * 40)

        risk_assessment = await self.generate_risk_score(self.findings)

        # Compile final report
        report = self.compile_comprehensive_report(risk_assessment)

        print(f"\n{'='*60}")
        print("[Orchestrator] Assessment complete")
        print(f"[Orchestrator] Overall Risk: {risk_assessment['risk_level']}")
        print(f"[Orchestrator] Report saved to: {self.assessment_id}_report.json")
        print(f"{'='*60}\n")

        return report

    def select_best_entry_point(self, entry_points: List[Dict]) -> Dict:
        """Select the most promising entry point for internal testing"""

        # Prioritize by risk level and type
        priority_order = {
            "credential": 3,
            "exposed_service": 2,
            "misconfiguration": 1
        }

        sorted_entries = sorted(
            entry_points,
            key=lambda x: (
                x.get("risk") == "high",
                priority_order.get(x.get("type"), 0)
            ),
            reverse=True
        )

        return sorted_entries[0] if sorted_entries else {"type": "default", "risk": "low"}

    def can_link_attack(self, entry: Dict, system: Dict) -> bool:
        """Determine if an external entry point can lead to internal system compromise"""

        # Check if the entry type could lead to this compromise
        if entry.get("type") == "credential":
            return True  # Credentials can lead to any system

        if entry.get("type") == "exposed_service":
            # Check if the exposed service relates to the compromised system
            return "service" in system.get("vulnerability", "").lower()

        return False

    def trace_attack_path(self, entry: Dict, system: Dict, internal_findings: Dict) -> List[str]:
        """Trace the attack path from entry to compromise"""

        path = [f"External: {entry.get('type')} discovered"]

        if entry.get("type") == "credential":
            path.append("Use leaked credentials for initial access")
        elif entry.get("type") == "exposed_service":
            path.append("Exploit exposed service vulnerability")

        # Add internal movement
        for movement in internal_findings.get("attack_paths", []):
            path.append(f"Lateral movement: {movement['from']} -> {movement['to']}")

        path.append(f"Compromise: {system.get('target')} with {system.get('access_level')} access")

        return path

    def calculate_impact(self, system: Dict, internal_findings: Dict) -> str:
        """Calculate the business impact of a compromise"""

        if system.get("access_level") == "admin":
            return "critical"

        # Check if sensitive data was found
        sensitive_data = internal_findings.get("sensitive_data_found", {})
        if sensitive_data.get("databases") or sensitive_data.get("credentials"):
            return "high"

        return "medium"

    def identify_critical_path(self, attack_chains: List[Dict]) -> Dict:
        """Identify the most critical attack path"""

        if not attack_chains:
            return {}

        # Sort by impact and feasibility
        critical = max(
            attack_chains,
            key=lambda x: (x["impact"] == "critical", len(x["attack_path"]))
        )

        return critical

    def generate_recommendations(self, attack_chains: List[Dict]) -> List[str]:
        """Generate security recommendations based on findings"""

        recommendations = []

        # Check for credential leaks
        if any("credential" in str(chain["entry_vector"].get("type")) for chain in attack_chains):
            recommendations.append("Implement credential scanning and rotation policies")
            recommendations.append("Enable multi-factor authentication on all accounts")

        # Check for exposed services
        if any("exposed_service" in str(chain["entry_vector"].get("type")) for chain in attack_chains):
            recommendations.append("Review and minimize external service exposure")
            recommendations.append("Implement Web Application Firewall (WAF)")

        # Check for lateral movement
        if any(len(chain["attack_path"]) > 3 for chain in attack_chains):
            recommendations.append("Implement network segmentation")
            recommendations.append("Deploy EDR solution for lateral movement detection")

        return recommendations

    def calculate_external_risk(self, external_findings: Dict) -> float:
        """Calculate risk from external exposure"""

        risk_score = 0.0

        # Check for leaked credentials
        leaked_creds = external_findings.get("surface_scan", {}).get("leaked_credentials", [])
        risk_score += len(leaked_creds) * 20

        # Check for missing security headers
        headers = external_findings.get("security_headers", {})
        missing_headers = sum(1 for v in headers.values() if not v)
        risk_score += missing_headers * 10

        # Check for exposed services
        exposed = external_findings.get("surface_scan", {}).get("exposed_services", [])
        risk_score += len(exposed) * 15

        return min(risk_score, 100)

    def calculate_internal_risk(self, internal_findings: Dict) -> float:
        """Calculate risk from internal vulnerabilities"""

        risk_score = 0.0

        vulns = internal_findings.get("vulnerabilities", {})
        risk_score += len(vulns.get("critical", [])) * 25
        risk_score += len(vulns.get("high", [])) * 15
        risk_score += len(vulns.get("medium", [])) * 5

        # Factor in compromised systems
        compromised = internal_findings.get("exploited_systems", [])
        risk_score += len(compromised) * 20

        return min(risk_score, 100)

    def calculate_chain_risk(self, combined_findings: Dict) -> float:
        """Calculate risk from attack chain feasibility"""

        chains = combined_findings.get("attack_chains", [])
        if not chains:
            return 0.0

        # More chains = higher risk
        risk_score = len(chains) * 15

        # Critical paths increase risk
        critical_path = combined_findings.get("most_critical_path", {})
        if critical_path.get("impact") == "critical":
            risk_score += 40

        return min(risk_score, 100)

    def calculate_business_impact(self, findings: Dict) -> float:
        """Calculate potential business impact"""

        impact_score = 0.0

        # Check for sensitive data exposure
        sensitive_data = findings.get("internal", {}).get("sensitive_data_found", {})
        if sensitive_data.get("databases"):
            impact_score += 40
        if sensitive_data.get("credentials"):
            impact_score += 30

        # Check for admin compromise
        exploited = findings.get("internal", {}).get("exploited_systems", [])
        admin_compromises = sum(1 for s in exploited if s.get("access_level") == "admin")
        impact_score += admin_compromises * 25

        return min(impact_score, 100)

    def get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""

        if risk_score >= 75:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    def identify_top_risks(self, findings: Dict) -> List[str]:
        """Identify top security risks"""

        risks = []

        # Check external findings
        if findings["external"].get("surface_scan", {}).get("leaked_credentials"):
            risks.append("Leaked credentials found in public sources")

        # Check internal findings
        if findings["internal"].get("vulnerabilities", {}).get("critical"):
            risks.append("Critical vulnerabilities in internal systems")

        # Check attack chains
        if findings["combined"].get("attack_chains"):
            risks.append("Viable attack paths from external to internal compromise")

        return risks[:5]  # Return top 5

    def compile_comprehensive_report(self, risk_assessment: Dict) -> Dict[str, Any]:
        """Compile the final comprehensive security report"""

        return {
            "assessment_id": self.assessment_id,
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "executive_summary": {
                "risk_level": risk_assessment["risk_level"],
                "risk_score": risk_assessment["overall_risk_score"],
                "top_risks": risk_assessment["top_risks"],
                "key_findings": self.summarize_key_findings()
            },
            "external_assessment": self.findings["external"],
            "internal_assessment": self.findings["internal"],
            "attack_chain_analysis": self.findings["combined"],
            "risk_assessment": risk_assessment,
            "recommendations": {
                "immediate": self.findings["combined"].get("recommendations", [])[:3],
                "short_term": self.findings["combined"].get("recommendations", [])[3:6],
                "long_term": self.generate_long_term_recommendations()
            }
        }

    def compile_external_only_report(self) -> Dict[str, Any]:
        """Compile report when only external testing was performed"""

        return {
            "assessment_id": self.assessment_id,
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "assessment_type": "external_only",
            "findings": self.findings["external"],
            "recommendations": [
                "No immediate entry points found",
                "Continue monitoring for exposed credentials",
                "Implement security headers if missing"
            ]
        }

    def summarize_key_findings(self) -> List[str]:
        """Summarize the most important findings"""

        summary = []

        # External findings
        entry_points = self.findings["external"].get("potential_entry_points", [])
        if entry_points:
            summary.append(f"Found {len(entry_points)} potential entry points from external scan")

        # Internal findings
        compromised = self.findings["internal"].get("exploited_systems", [])
        if compromised:
            summary.append(f"Successfully compromised {len(compromised)} internal systems")

        # Attack chains
        chains = self.findings["combined"].get("attack_chains", [])
        if chains:
            summary.append(f"Identified {len(chains)} complete attack chains")

        return summary

    def generate_long_term_recommendations(self) -> List[str]:
        """Generate long-term security recommendations"""

        return [
            "Implement continuous security monitoring",
            "Establish regular penetration testing schedule",
            "Develop incident response playbooks",
            "Conduct security awareness training",
            "Implement zero-trust architecture"
        ]