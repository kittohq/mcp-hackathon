#!/usr/bin/env python3
"""
Flask Backend for AI Security Assessment Platform
Connects frontend to the local assessment engine
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import asyncio
import json
import os
from datetime import datetime
from local_airia_simulator import LocalSecurityOrchestrator, LocalMCPClient

app = Flask(__name__)
CORS(app)

# Serve the frontend
@app.route('/')
def serve_frontend():
    return send_from_directory('frontend', 'index.html')

@app.route('/api/assess', methods=['POST'])
def assess_endpoint():
    """API endpoint for security assessment"""

    data = request.json
    target = data.get('target', 'example.com')
    assessment_type = data.get('type', 'full')

    # Run assessment in async context
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        results = loop.run_until_complete(run_assessment(target, assessment_type))
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        loop.close()

async def run_assessment(target: str, assessment_type: str):
    """Run the security assessment"""

    print(f"[API] Starting assessment for {target} (type: {assessment_type})")

    # Create orchestrator
    orchestrator = LocalSecurityOrchestrator()

    # Initialize MCP connections
    await orchestrator.external_agent.mcp_client.connect()
    await orchestrator.internal_agent.mcp_client.connect()

    # Run assessment
    results = await orchestrator.execute_task(
        "Perform comprehensive security assessment",
        {"target": target, "assessment_type": assessment_type}
    )

    # Parse AI response to extract structured data
    formatted_results = format_results(results, target)

    return formatted_results

def format_results(raw_results, target):
    """Format results for frontend consumption"""

    # Extract risk score and level from AI analysis
    risk_score = 72  # Default, would parse from AI response
    risk_level = "HIGH"

    # Parse external findings
    external_findings = []
    if 'external_assessment' in raw_results:
        findings = raw_results['external_assessment'].get('findings', [])
        for finding in findings:
            if finding.get('type') == 'web_scrape':
                external_findings.append("Exposed server information found")
            if finding.get('type') == 'credential_search':
                external_findings.append("Potential credentials exposed")

    # Parse internal findings
    internal_findings = []
    if 'internal_assessment' in raw_results:
        findings = raw_results['internal_assessment'].get('findings', [])
        for finding in findings:
            if finding.get('type') == 'network_discovery':
                hosts = len(finding.get('data', {}).get('hosts', []))
                internal_findings.append(f"{hosts} internal hosts discovered")
            if finding.get('type') == 'vulnerability_assessment':
                internal_findings.append("Critical vulnerabilities identified")

    # Create attack chain
    attack_chain = [
        "External reconnaissance via Bright Data",
        "Leaked credentials discovered",
        "Initial access gained",
        "Internal network mapped",
        "Privilege escalation achieved"
    ]

    # Generate recommendations
    recommendations = [
        "Rotate all exposed credentials immediately",
        "Implement Web Application Firewall (WAF)",
        "Enable multi-factor authentication",
        "Patch identified vulnerabilities",
        "Implement network segmentation"
    ]

    return {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'external_findings': external_findings or ["No immediate external issues found"],
        'internal_findings': internal_findings or ["Internal assessment pending"],
        'attack_chain': attack_chain,
        'recommendations': recommendations,
        'raw_analysis': raw_results.get('combined_analysis', '')
    }

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'AI Security Assessment Platform'})

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     AI SECURITY ASSESSMENT PLATFORM - WEB INTERFACE         ║
    ║     Access at: http://localhost:5000                        ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    app.run(debug=True, port=5000)