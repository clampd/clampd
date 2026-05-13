"""
Example: @clampd.guard() — Wrap any function with security.

Run: python examples/01_guard.py

To use a real gateway, remove the mock and set:
    CLAMPD_GATEWAY_URL=http://localhost:8080
    CLAMPD_API_KEY=your-key
"""
import sys

sys.path.insert(0, ".")

from examples.mock_gateway import install_mock_gateway

install_mock_gateway()

import clampd
from clampd.client import ClampdBlockedError

clampd.init(agent_id="guard-demo-agent")


@clampd.guard("db.query")
def query_database(sql: str) -> str:
    return f"Results for: {sql}"


@clampd.guard("drop_table")
def dangerous_delete(table: str) -> str:
    return f"Dropped {table}"


def main():
    # Allowed call
    print("--- Safe query ---")
    result = query_database(sql="SELECT name FROM users LIMIT 10")
    print(f"Result: {result}")

    # Blocked call
    print("\n--- Dangerous operation ---")
    try:
        dangerous_delete(table="users")
    except ClampdBlockedError as e:
        print("BLOCKED!")
        print(f"  Reason: {e.response.denial_reason}")
        print(f"  Risk: {e.response.risk_score}")


if __name__ == "__main__":
    main()
