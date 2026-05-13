# AUTO-GENERATED FROM services/crates/ag-common/src/categories.toml
# DO NOT EDIT BY HAND — run `cargo build -p ag-common` to regenerate.
"""Generated taxonomy data for the Python SDK.

Shapes:
  TAXONOMY:  category -> subcategory -> [operations]
  EGRESS:    category -> subcategory -> [operations that mean external egress]
              EGRESS[cat][sub] is always a subset of TAXONOMY[cat][sub].
Enums and helpers live in `clampd/taxonomy.py` (hand-written).
"""

from __future__ import annotations

TAXONOMY: dict[str, dict[str, list[str]]] = {
    'agent': {
        'a2a': ['read', 'write'],
        'config': ['read', 'write'],
        'delegate': ['write'],
        'spawn': ['write'],
    },
    'auth': {
        'credential': ['read', 'write', 'delete'],
        'oauth': ['read', 'write'],
        'secret': ['read', 'write', 'delete'],
        'token': ['read', 'write', 'delete', 'refresh'],
    },
    'browser': {
        'page': ['read', 'write'],
        'screenshot': ['read'],
    },
    'cloud': {
        'deploy': ['read', 'write', 'destructive'],
        'iam': ['read', 'write', 'delete'],
        'infra': ['read', 'write', 'destructive'],
    },
    'comms': {
        'email': ['read', 'send', 'delete'],
        'messaging': ['read', 'send', 'delete'],
        'notification': ['send'],
        'slack': ['read', 'send', 'delete'],
        'sms': ['read', 'send'],
    },
    'db': {
        'mutate': ['write', 'delete', 'destructive'],
        'query': ['read'],
        'schema': ['read', 'destructive'],
    },
    'exec': {
        'code': ['run'],
        'function': ['run'],
        'shell': ['run', 'destructive'],
    },
    'fs': {
        'blob': ['read', 'write', 'delete'],
        'file': ['read', 'write', 'delete'],
    },
    'llm': {
        'embedding': ['read', 'write'],
        'input': ['write'],
        'output': ['read'],
    },
    'net': {
        'dns': ['read'],
        'http': ['read', 'write'],
        'socket': ['read', 'write'],
    },
    'payment': {
        'billing': ['read', 'write'],
        'invoice': ['read', 'write'],
        'transaction': ['read', 'write', 'destructive'],
    },
    'scm': {
        'git': ['read', 'write', 'delete'],
    },
}

EGRESS: dict[str, dict[str, list[str]]] = {
    'agent': {
        'a2a': [],
        'config': [],
        'delegate': [],
        'spawn': [],
    },
    'auth': {
        'credential': [],
        'oauth': [],
        'secret': [],
        'token': [],
    },
    'browser': {
        'page': [],
        'screenshot': [],
    },
    'cloud': {
        'deploy': [],
        'iam': [],
        'infra': [],
    },
    'comms': {
        'email': ['send'],
        'messaging': ['send'],
        'notification': ['send'],
        'slack': ['send'],
        'sms': ['send'],
    },
    'db': {
        'mutate': [],
        'query': [],
        'schema': [],
    },
    'exec': {
        'code': [],
        'function': [],
        'shell': [],
    },
    'fs': {
        'blob': ['write'],
        'file': [],
    },
    'llm': {
        'embedding': [],
        'input': [],
        'output': [],
    },
    'net': {
        'dns': [],
        'http': ['write'],
        'socket': ['write'],
    },
    'payment': {
        'billing': [],
        'invoice': [],
        'transaction': [],
    },
    'scm': {
        'git': [],
    },
}

SENSITIVE_SOURCE: dict[str, dict[str, list[str]]] = {
    'agent': {
        'a2a': [],
        'config': [],
        'delegate': [],
        'spawn': [],
    },
    'auth': {
        'credential': ['read'],
        'oauth': ['read'],
        'secret': ['read'],
        'token': ['read'],
    },
    'browser': {
        'page': [],
        'screenshot': [],
    },
    'cloud': {
        'deploy': [],
        'iam': ['read'],
        'infra': [],
    },
    'comms': {
        'email': [],
        'messaging': [],
        'notification': [],
        'slack': [],
        'sms': [],
    },
    'db': {
        'mutate': [],
        'query': [],
        'schema': ['read'],
    },
    'exec': {
        'code': [],
        'function': [],
        'shell': [],
    },
    'fs': {
        'blob': [],
        'file': [],
    },
    'llm': {
        'embedding': [],
        'input': [],
        'output': [],
    },
    'net': {
        'dns': [],
        'http': [],
        'socket': [],
    },
    'payment': {
        'billing': [],
        'invoice': [],
        'transaction': [],
    },
    'scm': {
        'git': [],
    },
}

__all__ = ["TAXONOMY", "EGRESS", "SENSITIVE_SOURCE"]
