# AI Security Assessment Platform

Production-safe security testing using AI agents with Airia SDK, Bright Data MCP, and NodeZero MCP.

## Architecture

```
Airia Orchestrator
    ├── External Recon Agent → Bright Data MCP
    └── Internal Pentest Agent → NodeZero MCP
```

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your API keys
```

### 3. Run Demo
```bash
python main.py --demo
```

### 4. Run Real Assessment
```bash
python main.py example.com --type full
```

## How It Works

1. **External Reconnaissance** (via Bright Data MCP)
   - Discovers exposed services, leaked credentials, misconfigurations
   - Uses proxies for safe, undetectable scanning

2. **Internal Penetration** (via NodeZero MCP)
   - Simulates post-compromise lateral movement
   - Tests privilege escalation paths
   - Identifies sensitive data exposure

3. **Attack Chain Analysis** (via Airia Orchestration)
   - Links external vulnerabilities to internal compromises
   - Demonstrates real-world attack paths
   - Calculates business impact

## Key Features

- **MCP Auto-Discovery**: Agents automatically understand available tools
- **Production Safe**: Built-in safety controls and rate limiting
- **Complete Kill Chain**: External + Internal = Full attack simulation
- **No Prompt Engineering**: LLMs automatically map intents to MCP tools

## Project Structure

```
mcp-hackathon/
├── main.py                    # Entry point
├── requirements.txt           # Dependencies
├── .env.example              # Configuration template
├── src/
│   └── agents/
│       ├── external_recon_agent.py    # Bright Data integration
│       ├── internal_pentest_agent.py  # NodeZero integration
│       └── security_orchestrator.py   # Airia orchestration
└── README.md
```

## Uploading to Airia Visual Builder

After testing locally, upload the agent code to Airia's visual builder:

1. Go to [Airia Platform](https://airia.com)
2. Create new project
3. Upload agent files
4. Configure MCP connections
5. Deploy and test

## Assessment Output

Reports include:
- Risk score and level
- External vulnerabilities
- Internal attack paths
- Complete kill chains
- Remediation recommendations

## Demo Output

```
AI SECURITY ASSESSMENT PLATFORM
Powered by: Airia + Bright Data + NodeZero

[Demo] Phase 1: External Reconnaissance
  ✓ Found exposed admin panel at /admin
  ✓ Discovered leaked API key on GitHub
  ✓ Missing security headers detected

[Demo] Phase 2: Internal Penetration Testing
  ✓ Used API key for initial access
  ✓ Discovered 3 unpatched systems
  ✓ Achieved privilege escalation on database server

[Demo] Phase 3: Attack Chain Analysis
  ✓ Identified complete kill chain
  ✓ Path: GitHub leak → API access → Database compromise

ASSESSMENT SUMMARY
Risk Level: HIGH
Risk Score: 72/100

Top Risks:
  1. Leaked API credentials on GitHub
  2. Unpatched critical vulnerabilities
  3. Weak network segmentation

Most Critical Attack Path:
  → GitHub leak
  → API authentication
  → Internal access
  → Database compromise

Immediate Actions Required:
  ! Rotate all API keys immediately
  ! Patch critical vulnerabilities
  ! Enable MFA on all admin accounts
```

## Hackathon Value Proposition

- **Unique**: Combines external + internal testing (most tools do one or the other)
- **Production Safe**: Built for real environments, not just demos
- **Business Focused**: Shows actual impact, not just vulnerability lists
- **AI Native**: Leverages MCP for seamless tool integration