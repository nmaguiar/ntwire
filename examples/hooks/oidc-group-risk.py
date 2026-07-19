#!/usr/bin/env python3
"""Example executable authorizer hook: group-based risk scoring for OIDC
sessions, pass-through for SSH sessions.

Wire it up with:

    authorizer:
      exec: examples/hooks/oidc-group-risk.py
      timeout: 5s

The server invokes this once per /v1/auth (or /v1/auth/oidc) and /v1/renew
request, writing the AuthorizationInput JSON (see docs/PROTOCOL.md) to
stdin and reading an AuthorizationResult JSON from stdout. A non-zero exit,
malformed output, or timeout denies the request.
"""
import json
import sys

# Groups considered fully trusted: no changes to YAML grants or session TTL.
TRUSTED_GROUPS = {"engineering", "sre"}
# Groups considered higher-risk: keep only a safe subset of tunnels and
# shorten the session so a compromised or shared contractor account has a
# smaller window.
RESTRICTED_GROUPS = {"contractors"}
RESTRICTED_GROUP_ALLOWED_TUNNELS = {"reports"}
RESTRICTED_GROUP_TTL_SECONDS = 5 * 60


def main() -> None:
    request = json.load(sys.stdin)

    if request.get("auth_method") != "oidc":
        # SSH sessions (or any future non-OIDC method): accept the YAML
        # grants unchanged.
        json.dump({"allow": True, "allowed_tunnels": "*", "risk_score": 0}, sys.stdout)
        return

    groups = set(request.get("groups") or [])
    granted = request.get("granted_tunnels_by_yaml") or []

    if groups & TRUSTED_GROUPS:
        json.dump({"allow": True, "allowed_tunnels": "*", "risk_score": 0}, sys.stdout)
        return

    if groups & RESTRICTED_GROUPS:
        allowed = [t for t in granted if t in RESTRICTED_GROUP_ALLOWED_TUNNELS]
        json.dump({
            "allow": True,
            "allowed_tunnels": allowed,
            "ttl_seconds": RESTRICTED_GROUP_TTL_SECONDS,
            "risk_score": 40,
            "reason": "restricted group: narrowed grants and shortened session",
        }, sys.stdout)
        return

    # No recognized group claim: allow the YAML grants as-is but flag the
    # session as higher risk for downstream audit/alerting consumers of the
    # "audit" log line (risk_score does not itself change server behavior
    # beyond being logged).
    json.dump({
        "allow": True,
        "allowed_tunnels": "*",
        "risk_score": 60,
        "reason": "oidc identity has no recognized group claim",
    }, sys.stdout)


if __name__ == "__main__":
    main()
