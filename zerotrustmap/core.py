"""Conservative AWS identity-policy assertion graph; no effective access evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

MAX_POLICY = 4 * 1024 * 1024
MAX_STATEMENTS = 1000


class PolicyError(ValueError):
    pass


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_policy(raw: bytes) -> dict:
    if not 0 < len(raw) <= MAX_POLICY:
        raise PolicyError("policy input must be 1 to 4 MiB")
    try:
        data = json.loads(raw, object_pairs_hook=_unique_pairs)
    except json.JSONDecodeError as exc:
        raise PolicyError("invalid IAM JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("Statement"), (dict, list)):
        raise PolicyError("expected AWS IAM identity policy Statement")
    return data


def _strings(value, field: str) -> list[str]:
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or len(values) > 1000 or any(
            not isinstance(item, str) or not 1 <= len(item) <= 1024 for item in values):
        raise PolicyError(f"invalid {field} list")
    return values


def boundaries(path: Path | None) -> dict:
    if path is None:
        return {"principals": {}, "resources": {}}
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise PolicyError("boundary map must be a regular JSON file under 1 MiB")
    try:
        value = json.loads(path.read_bytes())
    except ValueError as exc:
        raise PolicyError("invalid boundary JSON") from exc
    if not isinstance(value, dict):
        raise PolicyError("boundary map must be an object")
    result = {}
    for section in ("principals", "resources"):
        entries = value.get(section, {})
        if not isinstance(entries, dict) or len(entries) > 10000 or any(
                not isinstance(key, str) or not isinstance(zone, str) or not 1 <= len(zone) <= 128
                for key, zone in entries.items()):
            raise PolicyError(f"invalid {section} boundary map")
        result[section] = entries
    return result


def analyze(raw: bytes, principal: str, boundary_map: dict | None = None,
            previous: dict | None = None) -> dict:
    if not isinstance(principal, str) or not re.fullmatch(r"arn:aws:iam::\d{12}:(?:role|user)/[\w+=,.@/-]{1,512}", principal):
        raise PolicyError("explicit IAM user or role ARN required")
    policy = load_policy(raw)
    statements = policy["Statement"] if isinstance(policy["Statement"], list) else [policy["Statement"]]
    if len(statements) > MAX_STATEMENTS:
        raise PolicyError("statement count exceeds 1000")
    zones = boundary_map or {"principals": {}, "resources": {}}
    edges = []
    denies = []
    issues = []
    indicators = []
    statement_hashes = []
    if policy.get("Version") != "2012-10-17":
        issues.append("policy Version is missing or not 2012-10-17; policy-language differences not evaluated")
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            issues.append(f"statement {index}: not an object")
            continue
        reference = f"#/Statement/{index}"
        statement_hashes.append(hashlib.sha256(json.dumps(statement, sort_keys=True).encode()).hexdigest())
        if "Principal" in statement:
            issues.append(f"{reference}: resource policy Principal unsupported; not evaluated")
            continue
        if "NotAction" in statement or "NotResource" in statement:
            issues.append(f"{reference}: NotAction/NotResource unsupported; not evaluated")
            continue
        effect = statement.get("Effect")
        if effect not in {"Allow", "Deny"}:
            issues.append(f"{reference}: invalid Effect")
            continue
        try:
            actions = _strings(statement.get("Action"), "Action")
            resources = _strings(statement.get("Resource"), "Resource")
        except PolicyError:
            issues.append(f"{reference}: Action/Resource layout unsupported")
            continue
        conditioned = "Condition" in statement
        if conditioned and not isinstance(statement["Condition"], dict):
            issues.append(f"{reference}: invalid Condition")
            continue
        for action in actions:
            for resource in resources:
                edge = {"principal": principal, "action": action, "resource": resource,
                        "effect": effect, "condition_present": conditioned,
                        "source_statement": reference,
                        "statement_sha256": statement_hashes[-1],
                        "principal_zone": zones.get("principals", {}).get(principal),
                        "resource_zone": zones.get("resources", {}).get(resource),
                        "interpretation": "policy statement assertion; effective access not evaluated"}
                (edges if effect == "Allow" else denies).append(edge)
                if len(edges) + len(denies) > 100000:
                    raise PolicyError("permission edge count exceeds 100000")
                if effect == "Allow" and (action == "*" or action.endswith(":*") or resource == "*"):
                    indicators.append({"type": "broad_allow_review", "source_statement": reference,
                                       "action": action, "resource": resource,
                                       "reason": "wildcard action or resource in Allow statement; other policies may restrict it"})
                p_zone, r_zone = edge["principal_zone"], edge["resource_zone"]
                if effect == "Allow" and p_zone and r_zone and p_zone != r_zone:
                    indicators.append({"type": "cross_boundary_review", "source_statement": reference,
                                       "principal_zone": p_zone, "resource_zone": r_zone,
                                       "reason": "operator-labelled zones differ; policy enforcement context not verified"})
    prior_hashes = set()
    if previous is not None:
        if not isinstance(previous, dict) or previous.get("schema_version") != 1 or previous.get("principal") != principal:
            raise PolicyError("previous report schema or principal mismatch")
        values = previous.get("statement_hashes")
        if not isinstance(values, list) or len(values) > MAX_STATEMENTS:
            raise PolicyError("previous statement hashes invalid")
        prior_hashes = set(values)
    return {"schema_version": 1, "principal": principal,
            "principal_type": "role" if ":role/" in principal else "user",
            "policy_version": policy.get("Version"),
            "source_sha256": hashlib.sha256(raw).hexdigest(), "statement_hashes": statement_hashes,
            "potential_allow_edges": edges, "deny_assertions_not_resolved": denies,
            "review_indicators": indicators, "issues": issues,
            "changes": {"new_statement_hashes": sorted(set(statement_hashes) - prior_hashes) if previous else [],
                        "not_observed_statement_hashes": sorted(prior_hashes - set(statement_hashes)) if previous else []},
            "nist_sp_800_207_review_topics": ["per-request authorization", "least privilege", "policy enforcement visibility"],
            "assessment_limit": "identity policy assertions only; SCPs, boundaries, sessions, resources, denies and conditions not evaluated for effective access"}


def analyze_file(path: Path, principal: str, boundary_map: dict | None = None,
                 previous: dict | None = None) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_POLICY:
        raise PolicyError("policy must be a regular JSON file of at most 4 MiB")
    return analyze(path.read_bytes(), principal, boundary_map, previous)
