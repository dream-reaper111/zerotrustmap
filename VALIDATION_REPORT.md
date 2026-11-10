# ZeroTrustMap validation report

Date: 2026-11-09. Tests use isolated, nonfunctional IAM policy fixtures. No AWS account or live identity data was accessed.

| Check | Actual result |
| --- | --- |
| Python compilation | Passed |
| `python3 -m unittest discover -s tests -v` | 5 passed, 0 failed, 0 skipped |
| Wildcard review, Deny separation, unsupported NotAction, condition labels, zone comparison, history, file import | Unit tested |
| AWS effective permissions or live API | Not evaluated or connected |
| Ruff/pytest | Unavailable in documented environment |

No Zero Trust certification, effective-access decision, or least-privilege compliance conclusion is claimed. Next validation requires authorized policy exports and other policy layers.
