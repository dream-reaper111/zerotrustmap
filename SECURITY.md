# Security model

Import only policies you are authorized to review. This offline tool does not request AWS credentials, modify IAM users or roles, or evaluate live permissions. Do not treat a wildcard review indicator as proof that a principal can exercise the action: AWS may restrict it through conditions, denies, boundaries, organization policies, or resource policies. Protect JSON reports as sensitive access-architecture information.

No authenticated API, audit database, or retention service exists in this first milestone. Operator labels and principal-to-policy ownership are supplied externally and not independently verified. The next milestone must record provenance and reviewer decisions before making remediation recommendations.
