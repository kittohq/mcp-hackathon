# Local Development Setup

Two options for running the security assessment platform:

## Option 1: Airia Cloud (Recommended for Hackathon)

Airia typically runs as a **cloud service** where you:
1. Upload your agents to their platform
2. Configure MCP connections through their UI
3. Deploy and run assessments via their orchestration engine

**Pros:**
- Full orchestration capabilities
- Built-in agent management
- Production-ready scaling

**Cons:**
- Requires Airia account and API keys
- Depends on their cloud infrastructure

## Option 2: Local Simulator (For Development)

Use `local_airia_simulator.py` to run everything locally without Airia's cloud.

### Setup Local Environment

1. **Install dependencies:**
```bash
pip install openai anthropic python-dotenv aiohttp
```

2. **Create `.env` file:**
```bash
# AI Model Configuration (choose one)
OPENAI_API_KEY=sk-...
# OR
ANTHROPIC_API_KEY=sk-ant-...

# Model selection
AI_MODEL=gpt-4  # or claude-3-opus, gpt-3.5-turbo
```

3. **Run local simulator:**
```bash
python local_airia_simulator.py example.com
```

### How Local Simulator Works

```python
# Instead of Airia SDK:
from airia import Agent  # ❌ Requires Airia cloud

# We use:
from local_airia_simulator import LocalAgent  # ✅ Runs locally
```

The simulator:
- **Replaces Airia SDK** with local agent framework
- **Simulates MCP servers** with mock responses
- **Uses OpenAI/Claude APIs** directly for AI reasoning
- **Maintains same architecture** as production code

### Local Architecture

```
Local Orchestrator (GPT-4/Claude)
    ├── External Recon Agent (GPT-4/Claude)
    │   └── Mock Bright Data MCP
    └── Internal Pentest Agent (GPT-4/Claude)
        └── Mock NodeZero MCP
```

## Comparison

| Feature | Airia Cloud | Local Simulator |
|---------|-------------|-----------------|
| Agent Orchestration | ✅ Full platform | ✅ Simulated |
| MCP Integration | ✅ Real MCPs | ⚠️ Mock MCPs |
| AI Models | ✅ Multiple options | ✅ OpenAI/Anthropic |
| Deployment | ☁️ Cloud only | 💻 Local only |
| Cost | 💰 Platform fees | 💰 Only AI API costs |
| Best For | Production/Demo | Development/Testing |

## For the Hackathon

### If you have Airia access:
1. Use the production code in `src/agents/`
2. Upload to Airia platform
3. Configure real MCP connections
4. Demo with actual Bright Data + NodeZero

### If you don't have Airia access:
1. Use `local_airia_simulator.py`
2. Run everything locally
3. Demo with simulated MCP responses
4. Show the same concepts and architecture

Both approaches demonstrate:
- AI agents coordinating security testing
- External + Internal attack simulation
- MCP protocol for tool integration
- Complete attack chain analysis

## Quick Start Commands

```bash
# Production (with Airia)
python main.py example.com

# Local development (without Airia)
python local_airia_simulator.py example.com

# Demo mode (no APIs needed)
python main.py --demo
```

## Key Insight

**Airia is primarily a cloud platform**, but the concepts work locally:
- Agents = AI-powered decision makers (works with any LLM API)
- MCP = Standardized tool interface (can be simulated)
- Orchestration = Agent coordination (can be coded locally)

The local simulator lets you develop and test without cloud dependencies!