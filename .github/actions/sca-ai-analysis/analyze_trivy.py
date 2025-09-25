import json
import os
from pathlib import Path
import cohere

summary = ""

try:
    with open("trivy-sca.json") as f:
        findings = json.load(f)
    results = findings.get("Results", [])
    summary = f"Found {len(results)} components scanned.\n\n"

    for result in results:
        if "Vulnerabilities" in result:
            summary += f"\n📦 {result['Target']}:\n"
            for vuln in result["Vulnerabilities"]:
                if vuln["Severity"] in ["HIGH", "CRITICAL"]:
                    summary += f" - {vuln['VulnerabilityID']} ({vuln['Severity']}): {vuln['Title']}\n"

except Exception as e:
    summary = f"⚠️ Failed to load or parse Trivy results: {e}"

prompt = f'''
You are a security expert. Analyze the following Trivy SCA findings and suggest remediation strategies for each vulnerability. Focus only on HIGH and CRITICAL severity issues.

{summary}
'''

try:
    co = cohere.Client(os.environ["COHERE_API_KEY"])
    response = co.chat(
        model="command-r-plus",
        message=prompt,
        temperature=0.3
    )
    ai_output = response.text
except Exception as e:
    ai_output = f"⚠️ AI analysis failed: {e}"

print("=== 🛠️ AI Remediation Suggestions ===")
print(ai_output)

Path("ai-suggestions.txt").write_text(ai_output)
