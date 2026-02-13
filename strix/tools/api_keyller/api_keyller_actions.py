"""API KEYLLER tool — check if API keys are alive or dead, scan text for leaked keys."""

from __future__ import annotations

import re
from typing import Any

import requests

from strix.tools.registry import register_tool

# ── Provider patterns for detection ──────────────────────────────────────

PROVIDERS = [
    {
        "name": "Stripe",
        "pattern": re.compile(r"^(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,}$"),
        "check": "_check_stripe",
    },
    {
        "name": "GitHub PAT",
        "pattern": re.compile(r"^ghp_[A-Za-z0-9]{36,}$"),
        "check": "_check_github",
    },
    {
        "name": "GitHub PAT (fine-grained)",
        "pattern": re.compile(r"^github_pat_[A-Za-z0-9_]{20,}$"),
        "check": "_check_github",
    },
    {
        "name": "AWS",
        "pattern": re.compile(r"^AKIA[0-9A-Z]{16}$"),
        "check": "_check_aws",
    },
    {
        "name": "OpenAI",
        "pattern": re.compile(r"^sk-(?!ant-)[A-Za-z0-9_-]{20,}$"),
        "check": "_check_openai",
    },
    {
        "name": "Anthropic",
        "pattern": re.compile(r"^sk-ant-[A-Za-z0-9_-]{20,}$"),
        "check": "_check_anthropic",
    },
    {
        "name": "Google AI (Gemini)",
        "pattern": re.compile(r"^AIzaSy[A-Za-z0-9_-]{33}$"),
        "check": "_check_google",
    },
    {
        "name": "Groq",
        "pattern": re.compile(r"^gsk_[A-Za-z0-9]{52,}$"),
        "check": "_check_groq",
    },
    {
        "name": "DeepSeek",
        "pattern": re.compile(r"^sk-[a-f0-9]{32,}$"),
        "check": "_check_deepseek",
    },
    {
        "name": "Fireworks AI",
        "pattern": re.compile(r"^fw_[A-Za-z0-9_-]{20,}$"),
        "check": "_check_fireworks",
    },
    {
        "name": "Together AI",
        "pattern": re.compile(r"^[a-f0-9]{64}$"),
        "check": "_check_together",
    },
    {
        "name": "Perplexity",
        "pattern": re.compile(r"^pplx-[a-f0-9]{48,}$"),
        "check": "_check_perplexity",
    },
    {
        "name": "xAI (Grok)",
        "pattern": re.compile(r"^xai-[A-Za-z0-9_-]{20,}$"),
        "check": "_check_xai",
    },
    {
        "name": "Replicate",
        "pattern": re.compile(r"^r8_[A-Za-z0-9]{37,}$"),
        "check": "_check_replicate",
    },
    {
        "name": "Stability AI",
        "pattern": re.compile(r"^sk-[A-Za-z0-9]{44,60}$"),
        "check": "_check_stability",
    },
    {
        "name": "HuggingFace",
        "pattern": re.compile(r"^hf_[A-Za-z0-9]{34,}$"),
        "check": "_check_huggingface",
    },
    {
        "name": "Cohere",
        "pattern": re.compile(r"^[A-Za-z0-9]{40}$"),
        "check": "_check_cohere",
    },
    {
        "name": "Mistral",
        "pattern": re.compile(r"^[A-Za-z0-9]{32}$"),
        "check": "_check_mistral",
    },
]

# ── Key extraction patterns (for scanning raw text) ──────────────────────

KEY_PATTERNS = {
    "Anthropic": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI": re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),
    "OpenAI (legacy)": re.compile(r"sk-[A-Za-z0-9]{40,60}"),
    "Google AI": re.compile(r"AIzaSy[A-Za-z0-9_-]{33}"),
    "HuggingFace": re.compile(r"hf_[A-Za-z0-9]{34,}"),
    "Groq": re.compile(r"gsk_[A-Za-z0-9]{52,}"),
    "AWS": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Stripe (secret)": re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    "Stripe (restricted)": re.compile(r"rk_live_[A-Za-z0-9]{24,}"),
    "Stripe (test)": re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
    "Slack (bot)": re.compile(r"xoxb-[0-9A-Za-z-]{50,}"),
    "Slack (user)": re.compile(r"xoxp-[0-9A-Za-z-]{50,}"),
    "GitHub PAT": re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    "GitHub PAT (fine-grained)": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    "Replicate": re.compile(r"r8_[A-Za-z0-9]{37,}"),
    "Fireworks AI": re.compile(r"fw_[A-Za-z0-9_-]{20,}"),
    "Perplexity": re.compile(r"pplx-[a-f0-9]{48,}"),
    "xAI": re.compile(r"xai-[A-Za-z0-9_-]{20,}"),
    "DeepSeek": re.compile(r"sk-[a-f0-9]{32}"),
}

TIMEOUT = 15


# ── Provider check functions ─────────────────────────────────────────────

def _check_openai(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        models = r.json().get("data", [])
        return True, f"Active — {len(models)} models accessible"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    if r.status_code == 429:
        return True, "Active — but rate-limited"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_anthropic(key: str) -> tuple[bool | None, str]:
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}],
        },
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code in (401, 403):
        err = r.json().get("error", {}).get("message", "")
        if "invalid" in err.lower() or "auth" in err.lower():
            return False, "Dead — invalid or revoked key"
        return True, f"Active — {err or 'permission limited'}"
    if r.status_code == 429:
        return True, "Active — but rate-limited"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_google(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://generativelanguage.googleapis.com/v1beta/models",
        params={"key": key},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 400:
        return False, "Dead — invalid or revoked key"
    if r.status_code == 403:
        return False, "Dead — forbidden"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_cohere(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.cohere.ai/v1/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_mistral(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.mistral.ai/v1/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_groq(key: str) -> tuple[bool | None, str]:
    r = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        json={
            "model": "llama-3.3-70b-versatile",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}],
        },
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    if r.status_code == 429:
        return True, "Active — but rate-limited"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_deepseek(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.deepseek.com/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_fireworks(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.fireworks.ai/inference/v1/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_together(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.together.xyz/v1/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_perplexity(key: str) -> tuple[bool | None, str]:
    r = requests.post(
        "https://api.perplexity.ai/chat/completions",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        json={
            "model": "sonar",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
        },
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    if r.status_code == 429:
        return True, "Active — but rate-limited"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_xai(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.x.ai/v1/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_replicate(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.replicate.com/v1/account",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        username = r.json().get("username", "unknown")
        return True, f"Active — account: {username}"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_stability(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.stability.ai/v1/user/account",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_huggingface(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://huggingface.co/api/whoami-v2",
        headers={"Authorization": f"Bearer {key}"},
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        name = r.json().get("name", "unknown")
        return True, f"Active — user: {name}"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_stripe(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.stripe.com/v1/balance",
        auth=(key, ""),
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        available = r.json().get("available", [{}])
        if available:
            currency = available[0].get("currency", "?")
            amount = available[0].get("amount", 0)
            return True, f"Active — balance: {amount} {currency}"
        return True, "Active — key works"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked key"
    if r.status_code == 429:
        return True, "Active — but rate-limited"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_github(key: str) -> tuple[bool | None, str]:
    r = requests.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=TIMEOUT,
    )
    if r.status_code == 200:
        login = r.json().get("login", "unknown")
        return True, f"Active — user: {login}"
    if r.status_code == 401:
        return False, "Dead — invalid or revoked token"
    if r.status_code == 403:
        return True, "Active — but forbidden (scope limited)"
    return False, f"Unknown status (HTTP {r.status_code})"


def _check_aws(key: str) -> tuple[bool | None, str]:
    return None, "AWS key ID detected — needs secret key to validate"


# ── Check function dispatch ──────────────────────────────────────────────

_CHECKERS = {
    "_check_openai": _check_openai,
    "_check_anthropic": _check_anthropic,
    "_check_google": _check_google,
    "_check_cohere": _check_cohere,
    "_check_mistral": _check_mistral,
    "_check_groq": _check_groq,
    "_check_deepseek": _check_deepseek,
    "_check_fireworks": _check_fireworks,
    "_check_together": _check_together,
    "_check_perplexity": _check_perplexity,
    "_check_xai": _check_xai,
    "_check_replicate": _check_replicate,
    "_check_stability": _check_stability,
    "_check_huggingface": _check_huggingface,
    "_check_stripe": _check_stripe,
    "_check_github": _check_github,
    "_check_aws": _check_aws,
}


def _detect_provider(key: str) -> dict | None:
    for provider in PROVIDERS:
        if provider["pattern"].match(key):
            return provider
    return None


def _mask_key(key: str) -> str:
    if len(key) > 16:
        return key[:8] + "..." + key[-4:]
    return "***"


def _extract_keys_from_text(text: str) -> list[dict]:
    found = []
    seen: set[str] = set()
    for provider_name, pattern in KEY_PATTERNS.items():
        for match in pattern.finditer(text):
            key = match.group(0)
            if key not in seen:
                seen.add(key)
                found.append({"key": key, "type": provider_name})
    return found


def _check_single_key(key: str) -> dict[str, Any]:
    key = key.strip()
    if not key:
        return {"alive": None, "detail": "Empty key", "provider": "N/A", "key_masked": "***"}

    masked = _mask_key(key)
    provider = _detect_provider(key)

    if provider is None:
        for name, fn in _CHECKERS.items():
            try:
                alive, detail = fn(key)
                if alive:
                    friendly = name.replace("_check_", "").replace("_", " ").title()
                    return {"alive": True, "detail": detail, "provider": friendly, "key_masked": masked}
            except requests.RequestException:
                continue
        return {"alive": None, "detail": "No provider match", "provider": "Unknown", "key_masked": masked}

    check_fn = _CHECKERS[provider["check"]]
    try:
        alive, detail = check_fn(key)
    except requests.Timeout:
        return {"alive": None, "detail": f"Timeout — {provider['name']}", "provider": provider["name"], "key_masked": masked}
    except requests.RequestException as exc:
        return {"alive": None, "detail": str(exc), "provider": provider["name"], "key_masked": masked}

    return {"alive": alive, "detail": detail, "provider": provider["name"], "key_masked": masked}


# ── Registered tools ─────────────────────────────────────────────────────

@register_tool(sandbox_execution=False)
def check_api_key(api_key: str) -> dict[str, Any]:
    """Check if an API key is alive or dead. Supports 17 providers."""
    try:
        result = _check_single_key(api_key)
        status = "ALIVE" if result["alive"] is True else "DEAD" if result["alive"] is False else "UNKNOWN"
        return {
            "success": True,
            "key_masked": result["key_masked"],
            "provider": result["provider"],
            "status": status,
            "alive": result["alive"],
            "detail": result["detail"],
            "message": f"{result['provider']}: {status} — {result['detail']}",
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"Key check failed: {e!s}"}


@register_tool(sandbox_execution=False)
def scan_api_keys(text: str) -> dict[str, Any]:
    """Extract and validate API keys found in text. Scans for 19 key patterns."""
    try:
        found = _extract_keys_from_text(text)
        if not found:
            return {
                "success": True,
                "keys_found": 0,
                "results": [],
                "message": "No API keys detected in the provided text.",
            }

        results = []
        for item in found:
            result = _check_single_key(item["key"])
            status = "ALIVE" if result["alive"] is True else "DEAD" if result["alive"] is False else "UNKNOWN"
            results.append({
                "key_masked": result["key_masked"],
                "detected_type": item["type"],
                "provider": result["provider"],
                "status": status,
                "alive": result["alive"],
                "detail": result["detail"],
            })

        alive_count = sum(1 for r in results if r["alive"] is True)
        dead_count = sum(1 for r in results if r["alive"] is False)

        return {
            "success": True,
            "keys_found": len(results),
            "alive_count": alive_count,
            "dead_count": dead_count,
            "results": results,
            "message": f"Found {len(results)} keys: {alive_count} alive, {dead_count} dead.",
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"Scan failed: {e!s}"}
