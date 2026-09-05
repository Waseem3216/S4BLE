# GitHub Actions: generate an Sable-ready Terraform plan artifact

This is intentionally stateless. The workflow generates `plan.json` and uploads it as a GitHub Actions artifact. Download the artifact and import it into Sable.

Copy `sable-plan.yml` into `.github/workflows/` in the Terraform repository and adapt the working directory/provider authentication as needed.
