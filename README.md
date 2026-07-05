# Aegis - a cloud-native mini-SIEM on AWS

Aegis ingests security telemetry from a live, deliberately attack-visible web
application (**CloudJuice**), runs a two-layer detection engine over it in near
real-time, and presents findings in a SOC console for triage. Everything is
provisioned with Terraform - no resource is created by hand.

<img width="8084" height="4164" alt="Aegis_Architecture drawio" src="https://github.com/user-attachments/assets/d87ffe3c-3875-4515-b761-2bdb12c79ccb" />


## What it does

- **CloudJuice** (ECS Fargate + ALB) is a real web app that *recognizes and
  logs* attack behavior but never executes attacker input - a sensor, not a
  victim. An external attack script drives realistic traffic at it.
- Security events flow through four authentic channels: app events
  (CloudWatch Logs), ALB access logs, VPC Flow Logs, and CloudTrail (all to S3).
- A **subscription filter** pushes app security events to the **ingestion
  Lambda**, which normalizes them, archives raw copies to the **S3 lake**, and
  enqueues them on **SQS** (with a DLQ).
- The **detection Lambda** runs a **declarative rule catalog** (detection-as-code:
  20+ rules covering SQLi, XSS, command injection, SSTI, Log4Shell, NoSQLi, XXE,
  SSRF, LFI/RFI, path traversal, IDOR, scanners, sensitive-file probes, and more)
  **plus a live statistical layer** (rate, brute-force, credential-stuffing, entropy,
  first-seen sources) using per-source windowed counters in **DynamoDB** - no trained
  model. Every rule is mapped to a **MITRE ATT&CK** technique, findings are enriched
  with **cached GeoIP** threat intel, and each is emitted in the **OCSF** Detection
  Finding schema. Findings go to DynamoDB, evidence bundles to S3, and anything
  `HIGH`+ fans out via **SNS** (to a Lambda that flags it, and optionally to email).
- **EventBridge** runs a scheduled correlation sweep for slow patterns.
- The **SOC console** (S3 static site → API Gateway → dashboard Lambda) is a
  multi-page, Kibana-style analyst workspace:
  - **Overview** - KPIs (findings, open incidents, high+critical, blocked sources,
    MTTA/MTTR), a findings-over-time chart, severity breakdown, and top sources.
  - **Discover** - a KQL-style search bar, global time picker, interactive
    histogram, a field sidebar with top values, filter pills, and expandable rows
    that reveal the full finding + OCSF evidence.
  - **Incidents** - findings grouped by source into triageable cases.
  - **Detections** - the rule catalog and a live **MITRE ATT&CK coverage matrix**.
  - **Threat Map** - a Leaflet map of attack origins from the GeoIP enrichment.
  - **Response** - the blocklist: block a source (the honeypot polls the list and
    starts returning `403`, logged as a finding) and **unblock** to restore it.

## Repo layout

```
app/            CloudJuice honeypot (dependency-free Node.js) + public/ storefront + Dockerfile
lambdas/        ingestion, detection (+detector.py catalog), alert, dashboard_api
spa/            SOC console (index.html, styles.css, app.js, catalog.js, api.js, config template)
attack/         external red-team script (stdlib only)
tests/          unit tests for the detection logic
infra/          Terraform for the entire stack
.github/        CI/CD workflow
```

## Prerequisites

- AWS Academy Learner Lab session (region `us-east-1`), Terraform ≥ 1.5,
  Docker, Python 3.12, and the AWS CLI.
- Provide your Learner Lab credentials via a local `.env` file (they rotate each
  session). Copy the template and fill it in:

```bash
cp .env.example .env
# then edit .env with your current Learner Lab session values
```

`.env` is gitignored; `.env.example` is the shareable template. (CI uses GitHub
Actions secrets instead, configured separately.)

## Deploy

Deployment is a two-phase apply: create the ECR repository, build and push the
CloudJuice image, then provision everything else. The two phases exist because
the ECS task references an image that must be pushed before the service starts.
Docker Desktop must be running for the image steps.

### Windows (PowerShell)

Run from the repo root:

```powershell
# 1. Load credentials from .env into this shell session
Get-Content .env | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
  $k, $v = $_ -split '=', 2
  Set-Item "Env:$($k.Trim())" $v.Trim()
}

# 2. (optional) run the detection tests
python -m unittest discover -s tests

# 3. Terraform lives in infra/
cd infra
terraform init                                                  # already done if re-running

# Phase 1: create the ECR repository
terraform apply -auto-approve -target="aws_ecr_repository.cloudjuice"

# Build and push the image
$REPO = terraform output -raw ecr_repository_url
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ($REPO -split '/')[0]
docker build -t "${REPO}:latest" ..\app
docker push "${REPO}:latest"

# Phase 2: provision everything else
terraform apply -auto-approve

# Show the URLs
terraform output
```

### macOS / Linux / Git Bash

Run from the repo root:

```bash
set -a; . ./.env; set +a          # load credentials
python3 -m unittest discover -s tests   # optional tests

cd infra
terraform init
terraform apply -auto-approve -target="aws_ecr_repository.cloudjuice"

REPO=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin "${REPO%/*}"
docker build -t "$REPO:latest" ../app
docker push "$REPO:latest"

terraform apply -auto-approve
terraform output
```

## Demo

From `infra/`, drive attacks at the deployed target (organic telemetry, nothing
is injected into the pipeline). The **campaign** scenario replays attacks from a
dozen spoofed source countries so the incident list and threat map fill up:

```powershell
# PowerShell
python ..\attack\attack.py --target (terraform output -raw cloudjuice_url) --scenario campaign
```

```bash
# bash
python3 ../attack/attack.py --target "$(terraform output -raw cloudjuice_url)" --scenario campaign
```

Other scenarios: `all`, or a single type - `sqli`, `xss`, `cmd`, `ssti`,
`log4shell`, `ssrf`, `nosqli`, `xxe`, `lfi`, `traversal`, `idor`, `scanner`,
`sensitive`, `recon`, `brute`, `credstuff`, `benign`. Add `--source-ip <ip>` to
attribute traffic to a specific origin.

Then open the **console URL** from `terraform output` and work the pages:
**Overview** for the situation, **Discover** to search/filter events, **Incidents**
to triage by source, **Detections** for the ATT&CK matrix, **Threat Map** for
origins, and **Response** to block a noisy source and watch it get `403`ed - then
unblock it.

## Redeploy after changes

App/container change (rebuild the image and make ECS pull it), from `infra/`:

```powershell
docker build -t "${REPO}:latest" ..\app        # $REPO from terraform output -raw ecr_repository_url
docker push "${REPO}:latest"
aws ecs update-service --cluster aegis-cluster --service aegis-cloudjuice --force-new-deployment
```

Infrastructure change: just re-run `terraform apply -auto-approve`.

## Teardown

From `infra/`:

```bash
terraform destroy -auto-approve
```

Buckets use `force_destroy` and ECR uses `force_delete`, so teardown is clean.

## Testing

```bash
python -m unittest discover -s tests    # stdlib, no install (python3 on macOS/Linux)
pytest -q                               # same tests under pytest (used in CI)
```

## Learner Lab notes (documented, not hidden)

- **Single shared role.** Role creation is not permitted, so every resource is
  attached to the pre-existing `LabRole`. In production each function would carry
  its own least-privilege role; the intended per-function policies are described
  in the design doc and marked as an environment-imposed deviation.
- **CloudTrail → S3 only.** The lab does not allow enabling CloudWatch Logs
  delivery on a trail, so the trail delivers to S3.
- **Email alerts are optional.** By default alerts use SNS → Lambda (no
  confirmation click needed). Setting `alert_email` (see `.env.example`) adds an
  SNS → email subscription; AWS sends one confirmation email you click once to
  activate. Apply it with `terraform apply -var "alert_email=$ALERT_EMAIL"`.
- **Rotating credentials.** Refresh the three GitHub Actions secrets
  (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) at the start
  of each lab session before the pipeline runs.
- **Public-IP tasks.** Fargate tasks run in public subnets with a locked security
  group (ALB is the only ingress) to avoid a NAT gateway; production would place
  them in private subnets behind NAT or VPC endpoints.
- **Console hosting.** The console is served as a public S3 static site. If the
  account enforces S3 Block Public Access, the public site will be blocked - in
  that case open `spa/index.html` locally after setting `API_BASE` in
  `spa/config.js` to the `api_base` output; the API's CORS allows this.
