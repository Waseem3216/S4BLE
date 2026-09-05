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
  assert.equal(result.analysis.metadata.authoritative, true);
  assert.equal(result.analysis.resources.length, 2);
  assert.ok(result.analysis.resources.some(r => r.id === 'module.app.aws_instance.api[0]'));
});

test('does not call a public RDS endpoint internet reachable without network evidence', async () => {
  const snapshot = { resources: [{ id: 'aws_db_instance.prod', type: 'aws_db_instance', name: 'prod', attributes: { publicly_accessible: true } }] };
  const result = await analyzeRequest({ text: JSON.stringify(snapshot) });
  const finding = result.analysis.findings.find(f => f.title === 'Public database endpoint enabled');
  assert.ok(finding);
  assert.equal(finding.confidence, 'confirmed');
  assert.match(finding.description, /does not by itself prove internet reachability/i);
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
