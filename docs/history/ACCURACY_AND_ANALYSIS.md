# S4BLE Analysis Accuracy Contract

Version 3.4 includes the corrections and tested boundaries listed in [UPDATE_NOTES_3.4.md](UPDATE_NOTES_3.4.md). The earlier 3.3 changes below remain historical context.

## What this build is designed to do

S4BLE is a static, evidence-based infrastructure review tool. It parses supported Terraform, CloudFormation, Kubernetes, YAML, JSON, and normalized snapshot inputs; builds only relationships supported by resource-specific evidence; and emits findings only when the imported artifact contains enough information to support the statement.

The analyzer is intentionally conservative. When provider defaults, account or organization policy, admission controls, runtime drift, remote modules, unknown plan values, or live network state can change the conclusion, S4BLE either lowers confidence, records the limitation, or avoids creating the finding.

## What no static IaC analyzer can guarantee

No static analyzer can provide a 100% guarantee that arbitrary infrastructure is secure or that every finding exactly matches the deployed environment from source files alone. Examples of information that can exist outside the imported artifact include:

- AWS Organizations / account-level policies, SCPs, permission boundaries, session policies, resource policies, and service-specific controls
- effective VPC routing, NACL behavior, DNS, firewall appliances, load balancers, private endpoints, and runtime reachability
- provider defaults, computed values, unknown Terraform plan values, remote modules, data sources, and drift
- Kubernetes admission mutations, policy engines, runtime identities, cluster configuration, and network plugins
- application-layer authentication, secrets, runtime configuration, and manually created resources

S4BLE therefore reports **evidence level**, **runtime verification status**, **rule coverage**, **confidence**, and **limitations** instead of claiming universal certainty.

## Input evidence levels

| Input | Evidence level | What S4BLE can responsibly claim |
|---|---|---|
| Terraform `show -json` plan | `planned-values` | High-confidence planned values, resource instances, plan actions, and declared references for the supplied plan |
| Terraform `show -json` state | `state-snapshot` | High-confidence values in the supplied state snapshot, but not proof of no drift |
| Raw Terraform `.tf` | `declaration-only` | Declared blocks and directly resolvable references; not fully evaluated provider/runtime behavior |
| CloudFormation JSON/YAML | `declaration-only` | Template declarations and intrinsic references; not live stack state |
| Kubernetes JSON/YAML | `declaration-only` | Manifest declarations, selectors, references, and explicit security settings; not admission-mutated/runtime state |
| Normalized snapshot | `user-supplied` | Exactly the supplied normalized resource/configuration/relationship evidence |

## Accuracy changes in 3.3

### Findings

- Security-group analysis recognizes world-open IPv4/IPv6 ingress, all-protocol/all-port exposure, administrative ports, and common database/cache/search ports.
- RDS public accessibility is described as a **public endpoint configuration**, not proof that the database is reachable from the internet.
- RDS `backup_retention_period = 0` is treated as disabled automated backups.
- S3 bucket-level Block Public Access settings are not treated as proof of effective public access because account and organization controls can override them.
- IAM `Resource: "*"` alone is no longer considered a finding because some AWS actions require wildcard resources. `Action: "*"`, broad service wildcards, risky `NotAction`, and unconditional wildcard trust principals are evaluated separately.
- Kubernetes checks avoid inventing a failure when fields are absent and admission/runtime policy could determine the effective value. Explicit privileged, host namespace, hostPath, root, dangerous capability, and unconfined seccomp configurations are evaluated.
- Generic category-based architecture edges were removed. Relationships require explicit imported evidence.

### PR review

PR risk is based on findings introduced by changed resources plus destructive/sensitive actions. Pre-existing findings on unrelated resources do not inflate change risk. The reviewer distinguishes introduced, pre-existing-on-changed-resource, and resolved findings.

### Evidence Score

The Evidence Score is a review-prioritization index, not a certification score. Repeated findings from the same rule have diminishing score impact, context-only advisories can be excluded from score impact, and unsupported-only scopes return **Not rated** rather than 100.

## Rule coverage

The response includes `analysis.metadata.coverage` with:

- imported managed resource count
- Terraform data-source count
- resources with an applicable built-in rule family
- resources without an applicable built-in rule family
- supported percentage
- applicable control-family count
- detected provider resource counts

Coverage indicates analyzer scope only. It is not a compliance percentage.

## Recommended production workflow

For Terraform, prefer machine-readable plan JSON:

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

For state review:

```bash
terraform show -json > state.json
```

For higher assurance beyond static IaC review, combine S4BLE with provider-native policy validation, live inventory/configuration APIs, IAM/access analyzers, runtime reachability checks, organization policy context, and organization-specific architecture standards.
