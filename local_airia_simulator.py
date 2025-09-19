"""
Local Airia Simulator - Run agents locally without Airia cloud
Uses OpenAI/Anthropic APIs directly to simulate Airia's agent framework
"""

import os
import asyncio
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod
import openai
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# AIRIA SIMULATOR CLASSES (Replace Airia SDK)
# ============================================================================

@dataclass
class AgentConfig:
    """Configuration for a local agent"""
    name: str
    description: str
    model: str = "gpt-4"
    temperature: float = 0.7
    max_tokens: int = 2000


class LocalAgent(ABC):
    """Base class that simulates Airia Agent locally"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.name = config.name
        self.description = config.description
        self.conversation_history = []

        # Initialize AI client based on model
        if "gpt" in config.model.lower():
            self.ai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            self.ai_type = "openai"
        elif "claude" in config.model.lower():
            self.ai_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            self.ai_type = "anthropic"
        else:
            raise ValueError(f"Unsupported model: {config.model}")

    async def think(self, prompt: str, context: Dict = None) -> str:
        """Use AI to process a prompt and return response"""

        # Build system prompt
        system_prompt = f"""You are {self.name}, an AI agent with the following role:
{self.description}

You have access to MCP tools that you can call. When you need to use a tool,
respond with JSON in this format:
{{
    "action": "call_tool",
    "tool": "tool_name",
    "params": {{...}}
}}

When providing analysis or responses, use this format:
{{
    "action": "respond",
    "message": "your response"
}}

Context: {json.dumps(context) if context else 'No additional context'}
"""

        # Call AI
        if self.ai_type == "openai":
            response = await self._call_openai(system_prompt, prompt)
        else:
            response = await self._call_anthropic(system_prompt, prompt)

        return response

    async def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        """Call OpenAI API"""
        response = self.ai_client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens
        )
        return response.choices[0].message.content

    async def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        """Call Anthropic API"""
        response = self.ai_client.messages.create(
            model=self.config.model,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens
        )
        return response.content[0].text

    @abstractmethod
    async def execute_task(self, task: str, params: Dict = None) -> Dict:
        """Execute a specific task - must be implemented by subclasses"""
        pass


class LocalMCPClient:
    """Simulates MCP client for local development"""

    def __init__(self, server_name: str):
        self.server_name = server_name
        self.tools = self._get_mock_tools()

    def _get_mock_tools(self) -> Dict:
        """Return mock MCP tools based on server"""
        if "brightdata" in self.server_name.lower():
            return {
                "web_scraper": {
                    "description": "Scrape web pages for content",
                    "params": ["url", "extract"]
                },
                "search_api": {
                    "description": "Search for exposed data",
                    "params": ["query", "limit"]
                },
                "proxy_request": {
                    "description": "Make requests through proxy",
                    "params": ["url", "method"]
                }
            }
        elif "nodezero" in self.server_name.lower():
            return {
                "network_scan": {
                    "description": "Scan internal network",
                    "params": ["targets", "scan_type"]
                },
                "vulnerability_scan": {
                    "description": "Scan for vulnerabilities",
                    "params": ["targets", "scan_level"]
                },
                "exploit": {
                    "description": "Exploit vulnerability",
                    "params": ["target", "vulnerability", "safe_mode"]
                }
            }
        return {}

    async def connect(self):
        """Simulate MCP connection"""
        print(f"[LocalMCP] Connected to {self.server_name} (simulated)")
        return True

    async def list_tools(self) -> List[Dict]:
        """List available tools"""
        return [
            {"name": name, "description": info["description"]}
            for name, info in self.tools.items()
        ]

    async def call(self, request: Dict) -> Dict:
        """Simulate MCP tool call"""
        tool = request.get("tool")
        params = request.get("params", {})

        print(f"[LocalMCP] Calling {self.server_name}.{tool} with params: {params}")

        # Return simulated responses
        if tool == "web_scraper":
            return {
                "status": "success",
                "headers": {
                    "Server": "nginx/1.19.0",
                    "X-Powered-By": "PHP/7.4"
                },
                "forms": ["login_form", "search_form"],
                "comments": ["<!-- TODO: Remove debug endpoint -->"]
            }
        elif tool == "search_api":
            return {
                "status": "success",
                "results": [
                    {
                        "url": "https://github.com/example/repo",
                        "snippet": "API_KEY=sk-1234567890abcdef"
                    }
                ]
            }
        elif tool == "network_scan":
            return {
                "status": "success",
                "hosts": ["192.168.1.10", "192.168.1.20", "192.168.1.100"],
                "services": {
                    "192.168.1.10": [22, 80, 443],
                    "192.168.1.20": [3306, 22],
                    "192.168.1.100": [445, 139, 3389]
                }
            }
        elif tool == "vulnerability_scan":
            return {
                "status": "success",
                "vulnerabilities": [
                    {
                        "host": "192.168.1.20",
                        "name": "MySQL weak password",
                        "severity": "critical",
                        "exploitable": True
                    }
                ]
            }

        return {"status": "success", "message": f"Simulated {tool} execution"}


# ============================================================================
# LOCAL AGENT IMPLEMENTATIONS
# ============================================================================

class LocalExternalReconAgent(LocalAgent):
    """Local version of External Recon Agent"""

    def __init__(self):
        config = AgentConfig(
            name="External Recon Agent",
            description="Performs external reconnaissance using Bright Data tools",
            model=os.getenv("AI_MODEL", "gpt-3.5-turbo")
        )
        super().__init__(config)
        self.mcp_client = LocalMCPClient("brightdata")

    async def execute_task(self, task: str, params: Dict = None) -> Dict:
        """Execute reconnaissance task"""

        # Use custom pentest name
        pentest_name = os.getenv("DEFAULT_PENTEST_NAME", "my-first-external-pentest")

        # Use AI to understand task and decide what to do
        prompt = f"""
Pentest Name: {pentest_name}
Task: {task}
Target: {params.get('target', 'unknown')}

You need to perform external reconnaissance. Available MCP tools:
{json.dumps(await self.mcp_client.list_tools(), indent=2)}

What tools should you call and in what order? Respond with your plan.
"""

        ai_response = await self.think(prompt, params)
        print(f"[AI Planning] {ai_response}")

        # Execute reconnaissance (simplified for local demo)
        results = {
            "target": params.get("target"),
            "findings": []
        }

        # Simulate tool calls based on AI decision
        if "web_scraper" in ai_response.lower():
            scrape_result = await self.mcp_client.call({
                "tool": "web_scraper",
                "params": {"url": f"https://{params.get('target')}"}
            })
            results["findings"].append({
                "type": "web_scrape",
                "data": scrape_result
            })

        if "search" in ai_response.lower() or "leak" in ai_response.lower():
            search_result = await self.mcp_client.call({
                "tool": "search_api",
                "params": {"query": f"site:{params.get('target')} password"}
            })
            results["findings"].append({
                "type": "credential_search",
                "data": search_result
            })

        # Use AI to analyze findings
        analysis_prompt = f"""
Analyze these reconnaissance findings and identify security issues:
{json.dumps(results, indent=2)}

Provide a security assessment with risk levels.
"""

        analysis = await self.think(analysis_prompt)
        results["analysis"] = analysis

        return results


class LocalInternalPentestAgent(LocalAgent):
    """Local version of Internal Pentest Agent"""

    def __init__(self):
        config = AgentConfig(
            name="Internal Pentest Agent",
            description="Performs internal penetration testing using NodeZero tools",
            model=os.getenv("AI_MODEL", "gpt-3.5-turbo")
        )
        super().__init__(config)
        self.mcp_client = LocalMCPClient("nodezero")

    async def execute_task(self, task: str, params: Dict = None) -> Dict:
        """Execute penetration testing task"""

        # Use AI to plan the pentest
        prompt = f"""
Task: {task}
Entry Point: {params.get('entry_point', 'unknown')}
External Intel: {params.get('external_intel', 'none')}

You need to perform internal penetration testing. Available MCP tools:
{json.dumps(await self.mcp_client.list_tools(), indent=2)}

Plan your penetration test approach.
"""

        ai_response = await self.think(prompt, params)
        print(f"[AI Planning] {ai_response}")

        results = {
            "entry_point": params.get("entry_point"),
            "findings": []
        }

        # Execute pentest steps
        if "network_scan" in ai_response.lower():
            scan_result = await self.mcp_client.call({
                "tool": "network_scan",
                "params": {"targets": ["192.168.0.0/16"], "scan_type": "safe"}
            })
            results["findings"].append({
                "type": "network_discovery",
                "data": scan_result
            })

        if "vulnerability" in ai_response.lower():
            vuln_result = await self.mcp_client.call({
                "tool": "vulnerability_scan",
                "params": {"targets": ["192.168.1.20"], "scan_level": "safe"}
            })
            results["findings"].append({
                "type": "vulnerability_assessment",
                "data": vuln_result
            })

        # AI analyzes the attack path
        analysis_prompt = f"""
Based on the penetration test results, identify:
1. Critical vulnerabilities
2. Potential attack paths
3. Business impact

Results: {json.dumps(results, indent=2)}
"""

        analysis = await self.think(analysis_prompt)
        results["analysis"] = analysis

        return results


class LocalSecurityOrchestrator(LocalAgent):
    """Local version of Security Orchestrator"""

    def __init__(self):
        config = AgentConfig(
            name="Security Orchestrator",
            description="Orchestrates security assessments by coordinating other agents",
            model=os.getenv("AI_MODEL", "gpt-3.5-turbo")
        )
        super().__init__(config)
        self.external_agent = LocalExternalReconAgent()
        self.internal_agent = LocalInternalPentestAgent()

    async def execute_task(self, task: str, params: Dict = None) -> Dict:
        """Orchestrate full security assessment"""

        target = params.get("target", "example.com")

        print(f"\n{'='*60}")
        print(f"Starting Local Security Assessment")
        print(f"Target: {target}")
        print(f"{'='*60}\n")

        # Phase 1: External Recon
        print("[Phase 1] External Reconnaissance")
        external_results = await self.external_agent.execute_task(
            "Perform external reconnaissance",
            {"target": target}
        )

        # Phase 2: Internal Pentest (if entry points found)
        print("\n[Phase 2] Internal Penetration Testing")
        internal_results = await self.internal_agent.execute_task(
            "Perform internal penetration test",
            {
                "entry_point": "leaked_api_key",
                "external_intel": external_results
            }
        )

        # Phase 3: Combined Analysis
        print("\n[Phase 3] Attack Chain Analysis")

        analysis_prompt = f"""
Combine the external and internal findings to identify complete attack chains:

External Findings:
{json.dumps(external_results, indent=2)}

Internal Findings:
{json.dumps(internal_results, indent=2)}

Provide:
1. Complete attack chains from external to internal
2. Risk assessment
3. Recommendations
"""

        final_analysis = await self.think(analysis_prompt)

        return {
            "target": target,
            "external_assessment": external_results,
            "internal_assessment": internal_results,
            "combined_analysis": final_analysis,
            "timestamp": str(asyncio.get_event_loop().time())
        }


# ============================================================================
# MAIN EXECUTION
# ============================================================================

async def run_local_assessment(target: str = "example.com"):
    """Run assessment using local simulator"""

    orchestrator = LocalSecurityOrchestrator()

    # Initialize MCP connections
    await orchestrator.external_agent.mcp_client.connect()
    await orchestrator.internal_agent.mcp_client.connect()

    # Run assessment
    results = await orchestrator.execute_task(
        "Perform comprehensive security assessment",
        {"target": target}
    )

    # Save results
    with open(f"local_assessment_{target.replace('.', '_')}.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print("\n" + "="*60)
    print("Assessment Complete!")
    print("="*60)

    return results


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    print("""
╔══════════════════════════════════════════════════════════════╗
║     LOCAL AIRIA SIMULATOR - Development Environment         ║
║     Running without Airia Cloud Platform                    ║
╚══════════════════════════════════════════════════════════════╝
    """)

    asyncio.run(run_local_assessment(target))