import json
import os
from pathlib import Path
from openai import OpenAI

try:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    ai_output = response.choices[0].message.content
except Exception as e:
    ai_output = f"⚠️ AI analysis failed: {e}"

summary = f"Found {len(findings.get('Results', []))} components scanned.\n\n"

for result in findings.get("Results", []):
    if "Vulnerabilities" in result:
        summary += f"\n📦 {result['Target']}:\n"
        for vuln in result["Vulnerabilities"]:
            if vuln["Severity"] in ["HIGH", "CRITICAL"]:
                summary += f" - {vuln['VulnerabilityID']} ({vuln['Severity']}): {vuln['Title']}\n"

prompt = f'''
You are a security expert. Analyze the following Trivy SCA findings and suggest remediation strategies for each vulnerability. Focus only on HIGH and CRITICAL severity issues.

{summary}
'''

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": prompt}]
)

ai_output = response.choices[0].message.content
print("=== 🛠️ AI Remediation Suggestions ===")
print(ai_output)

Path("ai-suggestions.txt").write_text(ai_output)
