# S4BLE 3.4 product update

## Focused additions

- **Resource Explorer:** filter resources by provider, category, findings, name, address, type, and imported tags. View declared size/location and open the existing resource drawer. Export exactly the filtered inventory as CSV; formula-like values are escaped for spreadsheet safety.
- **Cloud Guide:** six searchable lessons covering networks, compute, database recovery, identity, Kubernetes, and analysis evidence. Lessons connect to relevant imported resources and link to official documentation.
- **Practice lab:** AWS, Azure, GCP, and Kubernetes examples with two configurations each. The same production analyzer assesses examples separately from the current workspace. Source can be inspected and downloaded. Eight examples are also included in the archive.
- **Review checklist:** per-evidence, browser-local reviewed status, filters, and Markdown export. Changed finding evidence needs a new review. Checking an item never removes a finding or changes its score.
- Existing branding, assets, typography, color tokens, light/dark themes, panels, and architecture interactions are retained. Navigation uses compact labels/scrolling at smaller widths.

## Analysis corrections

- No-op Terraform plans use their explicit change list and never fabricate additions/deletions from an unrelated baseline.
- PR comparison uses individual finding evidence to distinguish a new rule instance from a pre-existing finding on the same resource.
- PR before/proposed views use the reviewed plan's before values, rather than unrelated browser baseline values.
- Terraform `.tf.json` uses the JSON configuration syntax parser; raw HCL continues to use the HCL parser.
- Module-local references cannot accidentally bind to same-named root resources. Caller argument bindings are preserved; ambiguous indexed references are omitted instead of selecting an arbitrary instance.
- Unknown Terraform values produce an explicit diagnostic. Sensitivity markers from both planned values and resource changes are honored.
- AWS port findings respect TCP/UDP protocols and do not confuse ICMP type/code numbers with administrative ports. Missing protocols are not guessed.
- GCP ingress checks ignore disabled, egress, or unresolved enforcement/direction settings and distinguish protocols, including numeric TCP/UDP values.
- Standalone Azure NSG rules are checked. Findings describe declared rules and acknowledge effective rule precedence.
- Kubernetes CronJob Pod templates and Secret references are assessed. Services match Pod-template labels rather than controller labels. Explicit ALL capability requests are covered.
- Kubernetes Secret data/stringData and last-applied annotation payloads are redacted in returned resources, including normalized snapshots with Secret objects.
- Database instances classify as data resources. Zero RDS retention findings apply to DB instances instead of incorrectly claiming that an RDS cluster has disabled backups.
- CloudFormation string interpolation edges require Sub; literal strings and explicitly overridden Sub variables do not create spurious dependencies.
- Multiple Kubernetes JSON files are analyzed together. Multiple independent plan/snapshot JSON files, mixed formats, and duplicate normalized resource identities return explicit errors instead of silently losing evidence.
- Custom numeric policy checks reject null, missing, blank, boolean, and unresolved values rather than coercing them to zero.
- Finding IDs include evidence, making distinct instances of the same rule identifiable.

## Usability and integration

- New clean routes are configured for Express and Vercel.
- Saved pre-3.4 analysis is recomputed from the saved normalized evidence when loaded; this correctly reports user-supplied snapshot evidence rather than retaining stale rule results.
- Resource and modal dialogs focus their close controls, trap keyboard focus, restore focus on close, and hide closed drawer controls from keyboard navigation.
- Page navigation returns to the page heading.
- No-op review empty states distinguish completed reviews from waiting for input.
- Browser export URLs remain alive briefly so the browser can finish starting a download.
- A dependency lockfile and additional tests are included. No new runtime dependency was added.

## Verification performed

- `npm run check`: passes for server, analyzer, and all browser JavaScript.
- `npm test`: **48 tests passed** (14 original tests retained, 34 additional checks).
- HTTP integration checks cover all five routes, JavaScript/CSS assets, health, JSON error handling, analysis, no-op review, and security headers.
- Browser checks: import a practice workspace, confirm resource/finding counts and topology categories, search imported tags, inspect the details drawer, save checklist progress, navigate/reload new routes, search lessons, run practice variants with the workspace still loaded, and review a no-change Terraform plan.
- Export content and the shared Blob-download helper are covered by automated checks. The in-app browser's download-event capture timed out, so actual filesystem delivery of browser exports was not independently confirmed in that browser.
- Desktop and mobile layouts and both themes were inspected. See the accompanying preview image.

## Accuracy boundaries

This is a static artifact analyzer, not a cloud inventory connector, runtime scanner, compliance certification, or cost engine. Coverage counts applicable rule families, not passing controls. Missing/unresolved properties, unprovided modules, drift, effective IAM, rule precedence, live network paths, and Kubernetes admission behavior can limit conclusions. Conservative unresolved graph edges remain absent. Read `ACCURACY_AND_ANALYSIS.md` alongside each import's diagnostics.

## Official references checked for this update

- [HashiCorp Terraform JSON format](https://developer.hashicorp.com/terraform/internals/json-format)
- [Terraform JSON configuration syntax](https://developer.hashicorp.com/terraform/language/syntax/json)
- [CloudFormation substitution references](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-sub.html)
- [AWS security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- [AWS IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS Auto Scaling concepts](https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-benefits.html)
- [Amazon RDS backups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html)
- [Azure NSG rules and precedence](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [Google Cloud firewall rules](https://docs.cloud.google.com/firewall/docs/firewalls)
- [Kubernetes CronJobs](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [Kubernetes security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes Secret practices](https://kubernetes.io/docs/concepts/security/secrets-good-practices/)
