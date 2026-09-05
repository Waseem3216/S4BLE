# Sable 3.2

Sable is an evidence-based cloud architecture analyzer for Terraform, CloudFormation, Kubernetes, and normalized infrastructure snapshots.

## Production analysis service

The original prototype parsed HCL and YAML with browser regular expressions. That was useful for a demo but was not reliable enough for production engineering decisions. Sable moves parsing and risk analysis into a Node.js service and uses real parsers:

- `@cdktf/hcl2json` for Terraform HCL2 syntax
- `js-yaml` for YAML, including common CloudFormation intrinsic tags
- native `JSON.parse` for Terraform machine-readable JSON, CloudFormation JSON, Kubernetes JSON, and Sable snapshots

The browser is now only responsible for the UI and visualization. The server owns parsing, evidence extraction, rule evaluation, scoring, and relationship construction.

## Start the app

Requirements:

- Node.js 20 or newer
- npm

From this folder:

```bash
npm install
npm start
```

Open:

```text
http://localhost:8080
```

Do not open `index.html` directly with `file://`; the production analyzer requires the local API service.

## Recommended Terraform workflow

For the most accurate Terraform result, analyze Terraform's machine-readable plan JSON rather than raw source text.

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

Then import `plan.json` into Sable.

For current Terraform state:

```bash
terraform show -json > state.json
```

HashiCorp documents `terraform show -json` as the machine-readable representation of plan/state data. Terraform plan JSON also includes configuration expressions and resource changes, which Sable uses for confirmed dependency edges and PR change impact.

### Sensitive data warning

`terraform show -json` can contain sensitive values in plaintext. Sable redacts values Terraform marks with `sensitive_values` / `after_sensitive` before returning analyzed data to the browser, but the source JSON itself still passes through the local analysis process. Run the service locally or inside a trusted environment.

## Accuracy model

Sable distinguishes the analysis mode instead of pretending all inputs have equal certainty.

### Terraform plan/state JSON

Mode: `terraform-plan-json` / `terraform-state-json`

- recursively walks root and child modules
- preserves full Terraform addresses such as `module.app.aws_instance.api[0]`
- reads planned/current values
- reads `resource_changes`
- reads configuration expression references
- honors Terraform JSON `format_version` major-version compatibility
- redacts fields marked sensitive by Terraform
- relationships derived from Terraform configuration references are marked `confirmed`

This is the preferred Terraform analysis path.

### Raw Terraform `.tf`

Mode: `terraform-static-source`

- parsed with an HCL2 parser, not regex
- supports multiple uploaded `.tf` files
- extracts declared resource blocks and direct HCL resource references
- does **not** claim to evaluate provider defaults, runtime unknown values, `for_each`/`count` instances, variable values, or resources inside remote/unprovided modules

The UI explicitly marks raw HCL analysis as non-authoritative. Use plan JSON when those runtime details matter.

### CloudFormation JSON/YAML

Mode: `declarative-template`

- parses `Resources`
- understands common intrinsic references including `Ref`, `GetAtt`, and `${LogicalId}` references inside substitutions
- builds confirmed resource edges only when the template declares a relationship
- does not invent runtime values absent from the template

### Kubernetes JSON/YAML

Mode: `declarative-manifest`

- supports multi-document YAML and Kubernetes List objects
- recognizes workload, Service, Ingress, ConfigMap, Secret, PVC, and ServiceAccount references
- builds confirmed relationships from selectors and explicit manifest references
- includes workload security checks such as privileged containers and host networking

### Sable normalized snapshots

Mode: `normalized-snapshot`

Input shape:

```json
{
  "workspace": "Production",
  "resources": [
    {
      "id": "aws_vpc.main",
      "type": "aws_vpc",
      "name": "main",
      "category": "network",
      "attributes": {}
    }
  ],
  "relationships": [
    {
      "source": "aws_vpc.main",
      "target": "aws_subnet.private_a",
      "label": "declared relationship",
      "confidence": "confirmed"
    }
  ]
}
```

Only supplied relationships are considered confirmed.

## Confirmed vs inferred architecture edges

Sable no longer silently fabricates an architecture graph.

- **Confirmed** edges are sourced from Terraform expressions, CloudFormation references, Kubernetes selectors/references, or explicit snapshot relationships.
- **Inferred** edges are returned separately and rendered with dashed, lower-emphasis lines. They are never presented as confirmed facts.

The optional inferred graph is intentionally conservative and exists to help exploration, not to replace evidence.

## Findings

Findings include:

- severity
- resource ID/address
- confidence
- description
- recommendation
- evidence object identifying the relevant property/rule
- source analysis mode

Rules currently cover evidence-backed examples across AWS, Azure, GCP, and Kubernetes, including public sensitive ports, public database endpoint configuration, explicitly disabled encryption/backups, wildcard IAM, and privileged Kubernetes workloads.

Sable avoids converting an absent property into a failure when provider defaults or out-of-scope controls could make the conclusion uncertain.

## Posture score

The score displayed in the UI is an **Sable evidence-weighted posture score**, not an AWS/Azure/GCP certification score.

Current weights:

- Critical: 20
- High: 10
- Medium: 5
- Low: 2

Lower-confidence findings receive reduced weight. The exact model is returned in `analysis.metadata.scoreModel` and exported reports so the score is auditable rather than opaque.

## PR reviewer

For production Terraform PR review, use machine-readable plan JSON:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

The review engine uses actual `resource_changes` actions when present. Human-readable `terraform plan` output is intentionally rejected because it is not a stable machine interface.

## API

Health check:

```text
GET /api/health
```

Analyze:

```text
POST /api/analyze
Content-Type: application/json
```

Body:

```json
{
  "text": "...",
  "files": [{ "name": "main.tf", "content": "..." }],
  "explicitType": "auto",
  "includeInferred": true
}
```

PR review:

```text
POST /api/review
```

Uses the same input plus an optional normalized baseline workspace.

## Production deployment notes

For an internet-facing deployment, additionally add:

- authenticated user sessions / SSO
- per-tenant storage isolation
- request rate limiting
- centralized audit logging
- encrypted persistence if uploads are stored
- malware/content-size controls for uploads
- secret-management integration
- TLS termination
- CI security scanning and dependency pinning
- a job queue if large workspaces are analyzed concurrently

The included server intentionally keeps analysis ephemeral and does not persist uploaded source files.

### Architecture navigation

The topology panel intentionally stays compact in the normal dashboard so very large workspaces cannot expand the page. Use **Maximize** for detailed architecture work. Inside the diagram:

- two-finger trackpad scroll pans the canvas;
- trackpad pinch (or Ctrl/Cmd + wheel) zooms around the pointer;
- dragging empty canvas space pans with a mouse or pen;
- `+`, `-`, the zoom slider, and **Fit view** provide explicit zoom controls;
- dense resource categories automatically wrap across internal columns instead of forming a single very tall stack.

## Production UI hardening

The interface adds production-oriented layout constraints for dense infrastructure workspaces. Large architecture graphs are contained in a bounded preview, expand into a focused inspection workspace, and support local pan/zoom without changing page dimensions. The responsive navigation, toolbars, findings, inventories, long labels, and relationship rows have also been hardened against clipping and overlap. See `UI_FIXES.md` for the validation summary.

## Sable 3.2: infrastructure intelligence

Version 3.1 keeps analysis request/response based. Optional browser preferences use `localStorage`:

- saved architecture views
- local Terraform/snapshot baseline
- local custom policy pack
- theme, zoom, confidence filters, and architecture lens

Clearing browser site storage removes those preferences. Exported reports/snapshots are ordinary files controlled by the user.

### New capabilities

- **Relationship Evidence** — inspect why a confirmed or inferred edge exists and see its evidence object.
- **Resource Details Drawer** — Overview, Relationships, Configuration, Findings, and Evidence tabs.
- **Architecture Search** — search by text or filters such as `type:`, `category:`, `risk:`, `provider:`, `name:`, and `changed:true`.
- **Architecture Lenses** — Architecture, Network, Security, Reliability, Observability, and Changes.
- **Confidence Filters** — independently show/hide confirmed and inferred relationships.
- **Blast Radius** — traverse upstream and downstream dependencies from a selected resource.
- **Incident View** — focused dependency-impact mode using the same deterministic graph.
- **Path Finder** — find directed or undirected relationship paths between two imported resources.
- **Architecture Mini-map** — quick navigation for large resource maps.
- **Saved Views** — store topology position, zoom, filters, and focus locally in the browser.
- **Analysis Coverage** — show resource/link counts, authority mode, diagnostics, providers, and unresolved/unsupported diagnostic counts.
- **Baseline Comparison** — compare the current imported workspace against a baseline saved in the browser, with clickable added/changed resources.
- **PR Architecture Impact** — visualize current, proposed, or overlay resource changes, filter to changes, and inspect before/after attributes per resource.
- **Custom Policy Packs** — import validated JSON guardrails, inspect expected/actual evidence, and evaluate them without altering the core posture score.
- **Ownership Context** — surface common owner/team/service/environment/repository metadata from imported tags and labels.
- **Control Context** — findings can show relevant security/reliability control context without claiming certification.
- **Architecture Report Export** — generate a self-contained HTML report from the current lens and confidence filters.

## 3.1 usability and functionality updates

- saved views are scoped to compatible workspaces and stale resource selections are discarded safely
- baseline actions are disabled until valid infrastructure exists and baseline removal requires confirmation
- baseline comparison clearly separates added, changed, removed, and unchanged resources
- architecture search supports keyboard navigation and shows result counts and risk context
- blast-radius and incident tools provide a resource picker when no resource is selected
- path finding includes source/target swap, confidence context, hop details, and clickable path resources
- relationship evidence uses a focused evidence view rather than irrelevant resource tabs
- the mini-map supports click-and-drag navigation
- coverage diagnostics are progressively disclosed so the dashboard remains compact
- policy packs are validated before use, large violation sets are collapsed, and each violation shows expected versus actual evidence
- PR architecture nodes are inspectable and expose current/proposed attribute differences
- resource inventory rows and applicable finding cards can open the resource directly in the architecture
- export and snapshot actions guard against empty or invalid analysis states

## Local policy pack format

A policy pack is plain JSON and is stored only in browser `localStorage` after import:

```json
{
  "name": "Production Guardrails",
  "rules": [
    {
      "id": "CUSTOM-DB-BACKUP",
      "title": "Database backup retention must be at least 7 days",
      "severity": "medium",
      "match": { "typeIncludes": "db" },
      "require": {
        "attribute": "backup_retention_period",
        "operator": "min",
        "value": 7
      }
    }
  ]
}
```

Supported local policy operators: `exists`, `equals`, `notEquals`, `min`, `max`, and `includes`.

These policies are separate from Sable's built-in evidence-backed analyzer and do not silently modify the posture score.

### Local architecture notes

Resource notes are optional and are saved only in browser `localStorage`. They are not synchronized to other users and are included in the locally generated HTML architecture report. Team collaboration/comments require a shared collaboration service and are intentionally outside this local-first build.

## Loader mascot update
The loading screen now uses `assets/sable-runner-motion-hardhat.webp`, a four-frame running sable animation with a construction hard hat. The original runner asset remains in `assets/` as a fallback/source reference.
