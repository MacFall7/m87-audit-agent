import os
import sys
import json
import time
import requests

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL = "claude-3-opus-20240229"

SPOT_RULES = [
    "No usage of eval() or exec()",
    "No hardcoded credentials or secrets",
    "No external API calls without validation",
    "Must include docstrings and type hints"
]

FORT_RULES = [
    "Function complexity must be <= 10 lines",
    "Must not mutate global state",
    "Disallowed use of dangerous imports (e.g., os.system)"
]

def load_code_from_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

def build_prompt(code, file_name):
    rules = "\n".join(f"- {r}" for r in SPOT_RULES + FORT_RULES)
    prompt = (
        f"You are a security governance agent auditing source code.\n\n"
        f"File: `{file_name}`\n\n"
        f"## Audit Rules (SPOT and FORT):\n\n"
        f"{rules}\n\n"
        f"## Code to Audit:\n\n"
        f"{code}\n\n"
        f"## Response Format:\n"
        f"Respond in JSON with:\n"
        f'- "spot_violations": List of SPOT rule violations\n'
        f'- "fort_violations": List of FORT rule violations\n'
        f'- "summary": Short paragraph summarizing audit\n\n'
        f"Return only the JSON. Begin."
    )
    return prompt

def call_claude(prompt: str):
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }

    payload = {
        "model": MODEL,
        "max_tokens": 1024,
        "temperature": 0.2,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    content = response.json()["content"][0]["text"]
    return json.loads(content)

def audit_file(file_path):
    print(f"\n🔍 Auditing: {file_path}")
    code = load_code_from_file(file_path)
    prompt = build_prompt(code, file_path)
    result = call_claude(prompt)
    return result

def main():
    if len(sys.argv) > 1:
        # Audit single file
        targets = [sys.argv[1]]
    else:
        # Audit all .py files in parent dir (excluding audits)
        base_dir = os.path.join(os.path.dirname(__file__), "..")
        targets = [
            os.path.join(base_dir, f)
            for f in os.listdir(base_dir)
            if f.endswith(".py") and not f.endswith(".audit.json")
        ]

    for file_path in targets:
        result = audit_file(file_path)
        file_name = os.path.basename(file_path)
        output_path = f"{file_name}.audit.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"✅ Audit complete for {file_name} → {output_path}")

if __name__ == "__main__":
    start = time.time()
    main()
    print(f"\n🕒 Total audit time: {round(time.time() - start, 2)}s")
