import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeRequest, reviewRequest } from '../engine/analyzer.mjs';

test('recursively reads Terraform child modules and confirmed configuration references', async () => {
  const plan = {
    format_version: '1.0', terraform_version: '1.9.0',
    planned_values: { root_module: {
      resources: [{ address: 'aws_vpc.main', mode: 'managed', type: 'aws_vpc', name: 'main', provider_name: 'registry.terraform.io/hashicorp/aws', values: { cidr_block: '10.0.0.0/16' }, sensitive_values: {} }],
      child_modules: [{ address: 'module.app', resources: [{ address: 'module.app.aws_instance.api[0]', mode: 'managed', type: 'aws_instance', name: 'api', values: { instance_type: 't3.micro' }, sensitive_values: {} }] }]
    }},
    configuration: { root_module: {
      resources: [{ address: 'aws_vpc.main', mode: 'managed', type: 'aws_vpc', name: 'main', expressions: {} }],
      module_calls: { app: { module: { resources: [{ address: 'aws_instance.api', mode: 'managed', type: 'aws_instance', name: 'api', expressions: { subnet_id: { references: ['aws_vpc.main.id'] } } }] } } }
    }},
    resource_changes: []
  };
  const result = await analyzeRequest({ text: JSON.stringify(plan) });
  assert.equal(result.analysis.metadata.authoritative, false);
  assert.equal(result.analysis.metadata.machineReadable, true);
  assert.equal(result.analysis.metadata.evidenceLevel, 'planned-values');
  assert.equal(result.analysis.resources.length, 2);
  assert.ok(result.analysis.resources.some(r => r.id === 'module.app.aws_instance.api[0]'));
});

test('does not call a publicly addressable RDS endpoint internet reachable without network evidence', async () => {
  const snapshot = { resources: [{ id: 'aws_db_instance.prod', type: 'aws_db_instance', name: 'prod', attributes: { publicly_accessible: true } }] };
  const result = await analyzeRequest({ text: JSON.stringify(snapshot) });
  const finding = result.analysis.findings.find(f => f.ruleId === 'S4BLE-AWS-RDS-001');
  assert.ok(finding);
  assert.equal(finding.confidence, 'confirmed');
  assert.match(finding.description, /does not prove internet reachability/i);
});

test('parses Kubernetes service selectors into confirmed relationships', async () => {
  const manifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: example/api:1
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  selector:
    app: api
  ports:
    - port: 80
`;
  const result = await analyzeRequest({ text: manifest, files: [{ name: 'k8s.yaml', content: manifest }] });
  assert.equal(result.analysis.resources.length, 2);
  assert.ok(result.analysis.graph.links.some(link => link.label === 'Service selector' && link.confidence === 'confirmed'));
});

test('links Kubernetes environment Secret and ConfigMap references', async () => {
  const manifest = `apiVersion: v1
kind: Secret
metadata:
  name: creds
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
        - name: api
          image: example/api:1
          env:
            - name: TOKEN
              valueFrom:
                secretKeyRef:
                  name: creds
                  key: token
          envFrom:
            - configMapRef:
                name: settings
`;
  const result = await analyzeRequest({ text: manifest, files: [{ name: 'k8s.yaml', content: manifest }] });
  assert.ok(result.analysis.graph.links.some(link => link.label === 'Environment secret reference'));
  assert.ok(result.analysis.graph.links.some(link => link.label === 'Environment ConfigMap reference'));
});

test('rejects human-readable Terraform plan text for automation', async () => {
  await assert.rejects(
    analyzeRequest({ text: 'Terraform will perform the following actions:\nPlan: 1 to add, 0 to change, 0 to destroy.' }),
    /not a stable machine interface/i
  );
});

test('PR review uses Terraform resource_changes when plan JSON is supplied', async () => {
  const plan = {
    format_version: '1.0',
    planned_values: { root_module: { resources: [{ address: 'aws_s3_bucket.new', type: 'aws_s3_bucket', name: 'new', values: {}, sensitive_values: {} }] } },
    configuration: { root_module: { resources: [] } },
    resource_changes: [{ address: 'aws_s3_bucket.new', type: 'aws_s3_bucket', name: 'new', change: { actions: ['create'], before: null, after: {}, before_sensitive: false, after_sensitive: {} } }]
  };
  const result = await reviewRequest({ text: JSON.stringify(plan) });
  assert.equal(result.review.counts.add, 1);
  assert.ok(result.review.diffs.some(d => d.action === 'add'));
});

test('PR risk does not penalize unchanged pre-existing findings', async () => {
  const plan = {
    format_version: '1.0',
    planned_values: { root_module: { resources: [
      { address: 'aws_security_group.existing', type: 'aws_security_group', name: 'existing', values: { ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }] }, sensitive_values: {} },
      { address: 'aws_s3_bucket.new', type: 'aws_s3_bucket', name: 'new', values: {}, sensitive_values: {} }
    ] } },
    configuration: { root_module: { resources: [] } },
    resource_changes: [
      { address: 'aws_security_group.existing', type: 'aws_security_group', name: 'existing', change: { actions: ['no-op'], before: { ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }] }, after: { ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }] }, before_sensitive: {}, after_sensitive: {} } },
      { address: 'aws_s3_bucket.new', type: 'aws_s3_bucket', name: 'new', change: { actions: ['create'], before: null, after: {}, before_sensitive: false, after_sensitive: {} } }
    ]
  };
  const result = await reviewRequest({ text: JSON.stringify(plan) });
  assert.ok(result.analysis.findings.some(f => f.ruleId === 'S4BLE-AWS-SG-002'));
  assert.ok(!result.review.findings.some(f => f.resource === 'aws_security_group.existing'));
});

test('world-open all-protocol security-group ingress is critical', async () => {
  const snapshot = { resources: [{ id: 'aws_security_group.open', type: 'aws_security_group', name: 'open', attributes: { ingress: [{ protocol: '-1', from_port: 0, to_port: 0, cidr_blocks: ['0.0.0.0/0'] }] } }] };
  const result = await analyzeRequest({ text: JSON.stringify(snapshot) });
  const finding = result.analysis.findings.find(f => f.ruleId === 'S4BLE-AWS-SG-001');
  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
});

test('IAM Resource star alone is not treated as a wildcard-action finding', async () => {
  const policy = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'logs:DescribeLogGroups', Resource: '*' }] });
  const snapshot = { resources: [{ id: 'aws_iam_policy.read', type: 'aws_iam_policy', name: 'read', attributes: { policy } }] };
  const result = await analyzeRequest({ text: JSON.stringify(snapshot) });
  assert.ok(!result.analysis.findings.some(f => /^S4BLE-AWS-IAM-00[12]$/.test(f.ruleId)));
});

test('IAM Action star is flagged with direct evidence', async () => {
  const policy = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] });
  const snapshot = { resources: [{ id: 'aws_iam_policy.admin', type: 'aws_iam_policy', name: 'admin', attributes: { policy } }] };
  const result = await analyzeRequest({ text: JSON.stringify(snapshot) });
  const finding = result.analysis.findings.find(f => f.ruleId === 'S4BLE-AWS-IAM-001');
  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
});

test('S3 Block Public Access finding does not claim effective public access', async () => {
  const snapshot = { resources: [{ id: 'aws_s3_bucket_public_access_block.assets', type: 'aws_s3_bucket_public_access_block', name: 'assets', attributes: { block_public_acls: false, block_public_policy: true, ignore_public_acls: true, restrict_public_buckets: true } }] };
  const result = await analyzeRequest({ text: JSON.stringify(snapshot) });
  const finding = result.analysis.findings.find(f => f.ruleId === 'S4BLE-AWS-S3-002');
  assert.ok(finding);
  assert.match(finding.description, /account or organization settings may still enforce stricter protection/i);
});

test('Kubernetes does not invent allowPrivilegeEscalation when the field is absent', async () => {
  const manifest = `apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: example/app:1
`;
  const result = await analyzeRequest({ text: manifest, files: [{ name: 'pod.yaml', content: manifest }] });
  assert.ok(!result.analysis.findings.some(f => f.ruleId === 'S4BLE-K8S-006'));
});

test('unsupported-only resource scopes are not given a misleading perfect score', async () => {
  const snapshot = { resources: [{ id: 'aws_vpc.main', type: 'aws_vpc', name: 'main', attributes: { cidr_block: '10.0.0.0/16' } }] };
  const result = await analyzeRequest({ text: JSON.stringify(snapshot) });
  assert.equal(result.analysis.score, null);
  assert.match(result.analysis.rating, /not rated/i);
  assert.equal(result.analysis.metadata.coverage.supportedResources, 0);
});

test('CloudFormation template is declaration evidence, not live runtime authority', async () => {
  const cfn = { Resources: { Bucket: { Type: 'AWS::S3::Bucket', Properties: {} } } };
  const result = await analyzeRequest({ text: JSON.stringify(cfn) });
  assert.equal(result.analysis.metadata.authoritative, false);
  assert.equal(result.analysis.metadata.evidenceLevel, 'declaration-only');
  assert.equal(result.analysis.metadata.runtimeVerified, false);
});
