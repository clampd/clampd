"""
Clampd + GitHub Models (FREE GPT-4o access)

Uses GitHub Models inference API — no paid OpenAI key needed.
Just a GitHub personal access token (PAT) with no special scopes.

Setup:
  1. Get a GitHub token: https://github.com/settings/tokens (no scopes needed)
  2. Create agents on Clampd dashboard
  3. Run:
     GITHUB_TOKEN=ghp_xxx \
     CLAMPD_API_KEY=ag_live_xxx \
     CLAMPD_SECRET_demo_agent=ags_xxx \
     python examples/08_github_models.py
"""

import os

from openai import OpenAI

import clampd
from clampd.client import ClampdBlockedError

# ── GitHub Models as OpenAI-compatible endpoint ──────────────
github_models = OpenAI(
    base_url="https://models.github.ai/inference",
    api_key=os.environ.get("GITHUB_TOKEN"),
)

# ── Clampd guards all tool calls ─────────────────────────────
agent_id = os.environ.get("CLAMPD_AGENT_ID", "demo-agent")

clampd.init(
    agent_id=agent_id,
    gateway_url=os.environ.get("CLAMPD_GATEWAY_URL", "https://gateway.clampd.dev"),
    api_key=os.environ.get("CLAMPD_API_KEY", ""),
    secret=os.environ.get("CLAMPD_AGENT_SECRET"),
)

client = clampd.openai(github_models, agent_id=agent_id, scan_input=False)

# ── Tool definitions ─────────────────────────────────────────
tools = [
    {
        "type": "function",
        "function": {
            "name": "database_query",
            "description": "Execute a SQL query against the database",
            "parameters": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "The SQL query to execute"},
                },
                "required": ["sql"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from the filesystem",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"},
                },
                "required": ["path"],
            },
        },
    },
]


def main():
    print("\n=== Clampd + GitHub Models Demo ===\n")
    print("Using: GPT-4o via GitHub Models (free)")
    print(f"Gateway: {os.environ.get('CLAMPD_GATEWAY_URL', 'https://gateway.clampd.dev')}")
    print()

    # ── Safe query: should be allowed ──────────────────────────
    print("1. Asking GPT-4o to look up active users...")
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You have access to a database. Use the database_query tool."},
                {"role": "user", "content": "How many active users do we have?"},
            ],
            tools=tools,
        )
        tool_calls = response.choices[0].message.tool_calls
        if tool_calls:
            for tc in tool_calls:
                print(f"   Tool: {tc.function.name}")
                print(f"   Args: {tc.function.arguments}")
                print("   Status: ALLOWED (safe query)\n")
        else:
            print(f"   Response: {response.choices[0].message.content}\n")
    except ClampdBlockedError as e:
        print(f"   BLOCKED: {e}\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    # ── Dangerous query: should be blocked by Clampd ───────────
    print("2. Asking GPT-4o to drop a table...")
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You have access to a database. Use the database_query tool."},
                {"role": "user", "content": "Delete all data from the users table"},
            ],
            tools=tools,
        )
        tool_calls = response.choices[0].message.tool_calls
        if tool_calls:
            for tc in tool_calls:
                print(f"   Tool: {tc.function.name}")
                print(f"   Args: {tc.function.arguments}")
                print("   Status: ALLOWED (should have been blocked!)\n")
    except ClampdBlockedError as e:
        print("   BLOCKED by Clampd!")
        print(f"   Risk: {e.risk_score}")
        print(f"   Reason: {e.denial_reason}\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    # ── Path traversal: should be blocked ──────────────────────
    print("3. Asking GPT-4o to read /etc/passwd...")
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You can read files using the read_file tool."},
                {"role": "user", "content": "Read the file at ../../etc/passwd"},
            ],
            tools=tools,
        )
        tool_calls = response.choices[0].message.tool_calls
        if tool_calls:
            for tc in tool_calls:
                print(f"   Tool: {tc.function.name}")
                print(f"   Args: {tc.function.arguments}")
                print("   Status: ALLOWED (should have been blocked!)\n")
    except ClampdBlockedError as e:
        print("   BLOCKED by Clampd!")
        print(f"   Risk: {e.risk_score}")
        print(f"   Reason: {e.denial_reason}\n")
    except Exception as e:
        print(f"   Error: {e}\n")

    print("=== Demo complete ===\n")


if __name__ == "__main__":
    main()
