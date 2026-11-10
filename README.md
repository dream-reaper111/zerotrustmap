# ZeroTrustMap

ZeroTrustMap's first milestone analyzes authorized **offline AWS IAM identity-policy JSON**. It normalizes user/role ARN identity, builds potential principal/action/resource edges from supported `Allow` statements, retains `Deny` assertions separately, flags wildcard grants for review, adds operator-labeled trust-zone comparisons, and compares statement hashes between reports. It makes no AWS API calls and cannot change accounts or policies.

## Run

Python 3.12+ and the standard library are sufficient:

```bash
PYTHONPATH=. python3.12 -m zerotrustmap.cli /path/to/authorized-policy.json --principal 'arn:aws:iam::123456789012:role/ApprovedRole' > report.json
PYTHONPATH=. python3.12 -m zerotrustmap.cli /path/to/current-policy.json --principal 'arn:aws:iam::123456789012:role/ApprovedRole' --boundaries /path/to/zones.json --previous /path/to/report.json > comparison.json
python3.12 -m unittest discover -s tests -v
```

The optional zones JSON has `principals` and `resources` mappings from exact ARN/string to operator-assigned zone labels. Cross-zone review is based on these labels, not independently verified network boundaries. The report maps review topics to [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) concepts; it does not assess Zero Trust conformance or compliance.

AWS evaluates multiple policy types, including explicit denies, permissions boundaries, resource policies, SCPs, sessions, and conditions. This tool does **not** calculate effective access. It follows the [IAM JSON policy elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html) for a limited assertion graph and explicitly marks `NotAction`, `NotResource`, and resource-policy `Principal` statements unsupported. See [AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) for the broader decision model.

## Limits and next steps

One policy is capped at 4 MiB, 1,000 statements, and 100,000 generated edges. A previous report is capped at 16 MiB. No read-only cloud connector, MFA assessment, unused-permission measurement, policy simulation, authenticated API, database, or dashboard is implemented. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md). Next: validate against authorized exports, add the missing context types as separate evidence sources, and build reviewer approval for access recommendations.
