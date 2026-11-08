# S4BLE 3.5.0

Infrastructure analysis and architecture exploration for **www.s4ble.com**. This archive contains the complete Node/Express application, browser assets, examples, tests, and deployment instructions. No build step or external API key is required. The ZIP is source code, not a static-only website: the analysis endpoints require the included server.

## Start

Use Node.js 22 or newer supported LTS, then run these commands from the extracted folder:

```sh
npm ci
npm test
npm start
```

Open http://localhost:8080. `PORT` and `HOST` are configurable. For development, `npm run dev` restarts the server on changes. `npm run check` checks JavaScript syntax.

## User workflows

- Import Terraform HCL/configuration JSON, machine-readable plan/state JSON, CloudFormation, Kubernetes YAML/JSON, or normalized snapshots. File selection and typing stay on the device until **Analyze workspace** or **Review PR risk** is selected.
- Explore category cards, then select **Show cloud context** to inspect connected resources. Arrow direction follows imported relationships, not observed network traffic. Confirmed and inferred links remain visually distinct. Use Fit view, zoom, pan, full screen, search, lenses, resource tracing, and relationship evidence.
- Review infrastructure changes against a saved baseline or a plan's before/after evidence. Empty and destroy plans are handled explicitly.
- Inspect/filter inventory, export Markdown/CSV/snapshots/reports, track reviewed findings, add local resource notes, and evaluate custom JSON guardrails.
- Open the Cloud Guide to analyze or load fictional example workspaces.

## Data handling

Analysis executes on the server serving this application. The application does not write imported source to server files or a database, and API responses are marked no-store. Hosting-provider logging/retention is separately controlled by the operator. Analysis results, workspace snapshots, baselines, notes, saved views, policies, and review progress can be stored in the browser. This is a single-browser workspace, with no accounts or cross-device synchronization.

Remove secrets before importing: sensitive-field redaction is best-effort and cannot recognize every secret. Use **Clear local data** in the footer to remove S4BLE browser data (theme preference is retained). Exported files remain wherever the user saved them. After an engine update, older saved results are not used as current results; **Refresh analysis** explicitly sends the saved normalized workspace for reassessment. Re-import an original plan when you need its original plan evidence.

## Limits and accuracy

100 files; 7 MB source; 2,000 resources. Node request bodies are limited to 8 MiB. Vercel deployments apply a smaller 4 MB application request/response budget; JSON encoding and saved baselines count toward that budget. Oversized imports receive a clear error. Requests time out in the browser after 45 seconds.

The analyzer checks supplied evidence. It does not connect to cloud accounts, verify runtime reachability, measure billing/utilization, prove compliance, or certify security. Unsupported controls and partial coverage remain visible. Architecture layout uses obstacle-aware routing; routes that cannot be safely drawn are disclosed and remain inspectable through evidence.

## Deployment and release

See [START_HERE.md](START_HERE.md), [VERCEL_DEPLOY.md](VERCEL_DEPLOY.md), [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md), and [RELEASE_NOTES.md](RELEASE_NOTES.md). Earlier documentation is preserved under `docs/history/` for historical context and does not override the current instructions.
