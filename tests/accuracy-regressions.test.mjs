import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeRequest, reviewRequest } from '../engine/analyzer.mjs';
import { practiceExample, filterInventory, resourceFacts, inventoryCsv, reviewKey } from '../public/product-core.js';
const analyze = doc => analyzeRequest({ text: JSON.stringify(doc) });
const resource = (type, attributes, id = `${type}.test`) => ({ id, type, name: id.split('.').at(-1), attributes });
const snapshot = (type, attributes) => analyze({ resources: [resource(type, attributes)] });
const sg = (port = 22, source = '0.0.0.0/0', protocol = 'tcp') => ({ protocol, from_port: port, to_port: port, cidr_blocks: [source] });
const tfResource = (address, values) => ({ address, type: address.split('.').at(-2), name: address.split('.').at(-1), mode: 'managed', values });

test('a no-op plan never falls back to additions or an unrelated saved baseline', async () => {
  const r = tfResource('aws_security_group.test', { ingress: [sg()] });
  for (const changes of [[], [{ ...r, change: { actions: ['no-op'], before: r.values, after: r.values } }]]) {
    const result = await reviewRequest({ text: JSON.stringify({ format_version: '1.0', planned_values: { root_module: { resources: [r] } }, resource_changes: changes }), baseline: { resources: [resource('aws_s3_bucket', {}, 'aws_s3_bucket.other')] } });
    assert.deepEqual(result.review.counts, { add: 0, change: 0, delete: 0 });
    assert.equal(result.review.riskScore, 0);
  }
});
test('PR review recognizes a second public rule as newly introduced on the same resource', async () => {
  const before = { ingress: [sg()] }, after = { ingress: [sg(), sg(3389)] };
  const result = await reviewRequest({ text: JSON.stringify({ format_version: '1.0', planned_values: { root_module: { resources: [tfResource('aws_security_group.test', after)] } }, resource_changes: [{ address: 'aws_security_group.test', type: 'aws_security_group', change: { actions: ['update'], before, after } }] }) });
  assert.equal(result.review.introducedFindings.length, 1);
  assert.equal(result.review.existingFindings.length, 1);
  assert.equal(new Set(result.analysis.findings.map(f => f.id)).size, 2);
});
test('ICMP numbers and absent protocols do not become administrative TCP ports', async () => {
  for (const protocol of ['icmp', '1', 'icmpv6', '58', '']) {
    const result = await snapshot('aws_security_group', { ingress: [sg(22, '0.0.0.0/0', protocol)] });
    assert.equal(result.analysis.findings.length, 0);
  }
  assert.ok((await snapshot('aws_security_group', { ingress: [sg(22, '::/0', '6')] })).analysis.findings.length);
});
test('AWS egress rules do not produce ingress findings', async () => {
  const result = await snapshot('aws_vpc_security_group_egress_rule', { ip_protocol: '-1', cidr_ipv4: '0.0.0.0/0' });
  assert.equal(result.analysis.findings.length, 0);
});
test('GCP ignores disabled and egress firewalls and respects protocol numbers', async () => {
  const attributes = { source_ranges: ['0.0.0.0/0'], allow: [{ protocol: 'tcp', ports: ['22'] }] };
  for (const extra of [{ disabled: true }, { direction: 'EGRESS' }, { direction: '${var.direction}' }, { disabled: '${var.disabled}' }, { allow: [{ protocol: 'icmp', ports: ['22'] }] }]) {
    assert.equal((await snapshot('google_compute_firewall', { ...attributes, ...extra })).analysis.findings.length, 0);
  }
  assert.ok((await snapshot('google_compute_firewall', { ...attributes, allow: [{ protocol: '6', ports: [] }] })).analysis.findings.some(f => f.severity === 'critical'));
});
test('standalone Azure NSG rules are assessed and ICMP is not treated as RDP', async () => {
  const attrs = { direction: 'Inbound', access: 'Allow', source_address_prefix: '*', destination_port_range: '3389', protocol: 'Tcp' };
  const result = await snapshot('azurerm_network_security_rule', attrs);
  assert.equal(result.analysis.findings.length, 1);
  assert.equal(result.analysis.metadata.coverage.supportedResources, 1);
  assert.equal((await snapshot('azurerm_network_security_rule', { ...attrs, protocol: 'Icmp' })).analysis.findings.length, 0);
});
test('CronJob security and Secret references are inspected inside jobTemplate', async () => {
  const cron = { apiVersion: 'batch/v1', kind: 'CronJob', metadata: { name: 'backup' }, spec: { jobTemplate: { spec: { template: { spec: { containers: [{ name: 'task', securityContext: { privileged: true }, envFrom: [{ secretRef: { name: 'creds' } }] }] } } } } } };
  const secret = { apiVersion: 'v1', kind: 'Secret', metadata: { name: 'creds' }, data: { password: 'DO_NOT_RETURN' }, stringData: { password: 'ALSO_SECRET' } };
  const result = await analyze({ apiVersion: 'v1', kind: 'List', items: [cron, secret] });
  assert.ok(result.analysis.findings.some(f => f.ruleId === 'S4BLE-K8S-005'));
  assert.ok(result.analysis.graph.links.some(l => l.label === 'Environment secret reference'));
  assert.doesNotMatch(JSON.stringify(result), /DO_NOT_RETURN|ALSO_SECRET/);
});
test('Kubernetes service selectors use Pod labels rather than controller labels', async () => {
  const deploy = { apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: 'app', labels: { app: 'web' } }, spec: { template: { spec: { containers: [] } } } };
  const service = { apiVersion: 'v1', kind: 'Service', metadata: { name: 'web' }, spec: { selector: { app: 'web' } } };
  assert.equal((await analyze({ apiVersion: 'v1', kind: 'List', items: [deploy, service] })).analysis.graph.links.length, 0);
});
test('Terraform JSON source files use the JSON configuration parser', async () => {
  const content = JSON.stringify({ resource: { aws_security_group: { test: { ingress: [sg()] } } } });
  const result = await analyzeRequest({ files: [{ name: 'main.tf.json', content }] });
  assert.equal(result.analysis.resources.length, 1);
  assert.ok(result.analysis.findings.length);
});
test('multiple non-Kubernetes JSON files are rejected rather than silently dropped', async () => {
  const content = JSON.stringify({ resources: [resource('aws_vpc', {})] });
  await assert.rejects(analyzeRequest({ files: [{ name: 'a.json', content }, { name: 'b.json', content }] }), /one JSON/);
});
test('multiple Kubernetes JSON files are all analyzed', async () => {
  const files = ['a', 'b'].map(name => ({ name: `${name}.json`, content: JSON.stringify({ apiVersion: 'v1', kind: 'Pod', metadata: { name }, spec: { containers: [{ name, securityContext: { privileged: true } }] } }) }));
  assert.equal((await analyzeRequest({ files })).analysis.findings.length, 2);
});
test('raw HCL is parsed and creates resource references', async () => {
  const result = await analyzeRequest({ files: [{ name: 'main.tf', content: 'resource "aws_security_group" "admin" {\n ingress {\n protocol = "tcp"\n from_port = 22\n to_port = 22\n cidr_blocks = ["0.0.0.0/0"]\n }\n}\nresource "aws_instance" "app" {\n vpc_security_group_ids = [aws_security_group.admin.id]\n}' }] });
  assert.equal(result.analysis.findings.length, 1);
  assert.equal(result.analysis.graph.links.length, 1);
});
test('Terraform module-local references do not bind to same-named root resources', async () => {
  const result = await analyze({ format_version: '1.0', planned_values: { root_module: { resources: [tfResource('aws_vpc.main', {})], child_modules: [{ address: 'module.app', resources: [tfResource('module.app.aws_vpc.main', {}), tfResource('module.app.aws_subnet.private', {})] }] } }, configuration: { root_module: { module_calls: { app: { module: { resources: [{ address: 'aws_subnet.private', expressions: { vpc_id: { references: ['aws_vpc.main.id'] } } }] } } } } } });
  assert.equal(result.analysis.graph.links[0].source, 'module.app.aws_vpc.main');
  assert.equal(result.analysis.graph.links[0].target, 'module.app.aws_subnet.private');
});
test('ambiguous instance references never choose an arbitrary indexed resource', async () => {
  const result = await analyze({ format_version: '1.0', planned_values: { root_module: { resources: [tfResource('aws_vpc.main[0]', {}), tfResource('aws_vpc.main[1]', {}), tfResource('aws_subnet.private', {})] } }, configuration: { root_module: { resources: [{ address: 'aws_subnet.private', expressions: { vpc_id: { references: ['aws_vpc.main'] } } }] } } });
  assert.equal(result.analysis.graph.links.length, 0);
});
test('databases classify as data rather than generic instances', async () => {
  const result = await snapshot('aws_db_instance', {});
  assert.equal(result.analysis.resources[0].category, 'data');
});
test('zero cluster retention does not claim that an RDS cluster disabled backups', async () => {
  assert.ok(!(await snapshot('aws_rds_cluster', { backup_retention_period: 0 })).analysis.findings.some(f => f.ruleId === 'S4BLE-AWS-RDS-003'));
});
test('Terraform sensitive values are redacted in resources and change evidence', async () => {
  const attrs = { password: 'VERY_PRIVATE', storage_encrypted: false };
  const r = { ...tfResource('aws_db_instance.test', attrs), sensitive_values: { password: true } };
  const result = await analyze({ format_version: '1.0', planned_values: { root_module: { resources: [r] } }, resource_changes: [{ ...r, change: { actions: ['create'], after: attrs, after_sensitive: { password: true } } }] });
  assert.doesNotMatch(JSON.stringify(result), /VERY_PRIVATE/);
});
for (const provider of ['aws', 'azure', 'gcp', 'kubernetes']) test(`${provider} practice examples yield findings, then remove the illustrated findings`, async () => {
  const before = await analyzeRequest({ text: practiceExample(provider).text });
  const after = await analyzeRequest({ text: practiceExample(provider, true).text });
  assert.ok(before.analysis.findings.length > 0);
  assert.equal(after.analysis.findings.length, 0);
});
test('inventory filters compose and exported cells neutralize spreadsheet formulas', () => {
  const resources = [resource('aws_instance', { instance_type: 't3.small', tags: { Owner: 'Platform' } }, 'aws_instance.app'), resource('aws_db_instance', {}, 'aws_db_instance.db')].map(r => ({ ...r, provider: 'AWS', category: r.type === 'aws_instance' ? 'compute' : 'data' }));
  assert.equal(filterInventory(resources, [{ resource: resources[0].id }], { search: 'platform', provider: 'AWS', category: 'compute', risk: 'findings' }).length, 1);
  assert.equal(filterInventory(resources, [], { search: 'missing' }).length, 0);
  assert.equal(resourceFacts(resources[0]).location, 'Not supplied');
  const csv = inventoryCsv([{ ...resources[0], name: '=WEBSERVICE("bad")' }], []);
  assert.match(csv, /'=/);
  assert.match(csv, /""bad""/);
});
test('checklist review identity changes with evidence and workspace but not object key order', () => {
  const w = { workspace: 'one', sourceType: 'snapshot', resources: [{ id: 'a' }] };
  const f = { ruleId: 'rule', resource: 'a', evidence: { value: 22, attribute: 'port' } };
  assert.equal(reviewKey(w, f), reviewKey(w, { ...f, evidence: { attribute: 'port', value: 22 } }));
  assert.notEqual(reviewKey(w, f), reviewKey(w, { ...f, evidence: { ...f.evidence, value: 3389 } }));
  assert.notEqual(reviewKey(w, f), reviewKey({ ...w, workspace: 'two' }, f));
});

test('PR architecture baseline is reconstructed from plan before values', async () => {
  const old = { storage_encrypted: false }, next = { storage_encrypted: true };
  const result = await reviewRequest({ text: JSON.stringify({ format_version: '1.0', planned_values: { root_module: { resources: [tfResource('aws_db_instance.test', next)] } }, resource_changes: [{ address: 'aws_db_instance.test', type: 'aws_db_instance', change: { actions: ['update'], before: old, after: next } }] }), baseline: { resources: [resource('aws_vpc', {}, 'aws_vpc.unrelated')] } });
  assert.equal(result.review.baselineResources.length, 1);
  assert.equal(result.review.baselineResources[0].attributes.storage_encrypted, false);
  assert.equal(result.review.resolvedFindings.length, 1);
});
test('plan change sensitivity is honored even if planned sensitivity is empty', async () => {
  const attrs = { password: 'PRIVATE_FALLBACK' };
  const result = await analyze({ format_version: '1.0', planned_values: { root_module: { resources: [{ ...tfResource('aws_db_instance.test', attrs), sensitive_values: {} }] } }, resource_changes: [{ address: 'aws_db_instance.test', type: 'aws_db_instance', change: { actions: ['create'], after: attrs, after_sensitive: { password: true }, after_unknown: { endpoint: true } } }] });
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_FALLBACK/);
  assert.ok(result.analysis.diagnostics.some(d => d.code === 'terraform-unknown-values'));
});
test('module argument bindings resolve caller resource identities', async () => {
  const result = await analyze({ format_version: '1.0', planned_values: { root_module: { resources: [tfResource('aws_vpc.main', {})], child_modules: [{ address: 'module.app', resources: [tfResource('module.app.aws_subnet.private', {})] }] } }, configuration: { root_module: { module_calls: { app: { expressions: { vpc_id: { references: ['aws_vpc.main.id'] } }, module: { resources: [{ address: 'aws_subnet.private', expressions: { vpc_id: { references: ['var.vpc_id'] } } }] } } } } } });
  assert.equal(result.analysis.graph.links[0].source, 'aws_vpc.main');
  assert.equal(result.analysis.graph.links[0].target, 'module.app.aws_subnet.private');
});
test('CloudFormation YAML parses tagged references and security-group ingress', async () => {
  const text = 'Resources:\n  Vpc:\n    Type: AWS::EC2::VPC\n    Properties:\n      CidrBlock: 10.0.0.0/16\n  Sg:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n      VpcId: !Ref Vpc\n      SecurityGroupIngress:\n        - IpProtocol: tcp\n          FromPort: 22\n          ToPort: 22\n          CidrIp: 0.0.0.0/0\n';
  const result = await analyzeRequest({ text });
  assert.ok(result.analysis.findings.some(f => f.ruleId === 'S4BLE-AWS-SG-002'));
  assert.ok(result.analysis.graph.links.some(l => l.source === 'cfn.Vpc' && l.target === 'cfn.Sg'));
});

test('combined upload preview text does not break Kubernetes multi-file JSON detection', async () => {
  const files = ['a', 'b'].map(name => ({ name: `${name}.json`, content: JSON.stringify({ apiVersion: 'v1', kind: 'ConfigMap', metadata: { name } }) }));
  const result = await analyzeRequest({ text: files.map(f => `# ---- ${f.name} ----\n${f.content}`).join('\n'), files });
  assert.equal(result.analysis.resources.length, 2);
});
test('mixed file formats are rejected by the API', async () => {
  await assert.rejects(analyzeRequest({ files: [{ name: 'a.tf', content: 'resource "aws_vpc" "a" {}' }, { name: 'b.json', content: '{}' }] }), /one infrastructure format/);
});
test('duplicate resource identities are rejected instead of overwriting evidence', async () => {
  await assert.rejects(analyze({ resources: [resource('aws_instance', {}), resource('aws_instance', { associate_public_ip_address: true })] }), /Duplicate resource/);
});
test('CloudFormation only interpolates Sub strings and honors Sub variable overrides', async () => {
  const resources = { Bucket: { Type: 'AWS::S3::Bucket' }, App: { Type: 'AWS::EC2::Instance', Properties: { Description: '${Bucket}' } } };
  assert.equal((await analyze({ Resources: resources })).analysis.graph.links.length, 0);
  resources.App.Properties.Description = { 'Fn::Sub': ['${Bucket}', { Bucket: 'literal' }] };
  assert.equal((await analyze({ Resources: resources })).analysis.graph.links.length, 0);
  resources.App.Properties.Description = { 'Fn::Sub': '${Bucket.Arn}' };
  assert.equal((await analyze({ Resources: resources })).analysis.graph.links.length, 1);
});


test('uploaded files are authoritative over preview text', async () => {
  const actual = JSON.stringify({ resources: [resource('aws_vpc', {}, 'aws_vpc.actual')] });
  const result = await analyzeRequest({ text: '{bad preview', files: [{ name: 'actual.json', content: actual }] });
  assert.equal(result.analysis.resources[0].id, 'aws_vpc.actual');
});

test('invalid request shapes and resources receive actionable errors', async () => {
  for (const body of [null, [], 'source', { text: 123 }, { files: 'source' }, { files: [null] }, { files: [{ content: {} }] }, { baseline: { resources: [null] } }]) {
    await assert.rejects(analyzeRequest(body), /object|string|array|text content/);
  }
  await assert.rejects(analyze({ resources: [null] }), /resource must be an object/);
  await assert.rejects(analyze({ resources: Array.from({ length: 2001 }, (_, i) => resource('aws_vpc', {}, `vpc.${i}`)) }), /maximum of 2000 resources/);
});

test('recursive aliases and deeply nested input are rejected before inspection', async () => {
  await assert.rejects(analyzeRequest({ text: `resources: &resources
  - id: loop
    type: aws_vpc
    attributes:
      again: *resources
` }), /Circular YAML aliases/);
  let deep = {};
  for (let i = 0; i < 90; i++) deep = { nested: deep };
  await assert.rejects(analyze({ resources: [resource('aws_vpc', deep)] }), /maximum nesting depth/);
});

test('parsing failures do not echo sensitive source text', async () => {
  for (const body of [{ text: '{"password":"VERY_PRIVATE",broken}' }, { text: `resources:
  - password: VERY_PRIVATE
   broken: [
`, filename: 'source.yaml' }]) {
    await assert.rejects(analyzeRequest(body), error => !error.message.includes('VERY_PRIVATE'));
  }
});

test('Kubernetes typed lists expand into resources and preserve findings', async () => {
  const result = await analyze({ apiVersion: 'v1', kind: 'PodList', items: [{ metadata: { name: 'app' }, spec: { containers: [{ name: 'web', securityContext: { privileged: true } }] } }] });
  assert.equal(result.analysis.resources[0].type, 'kubernetes_pod');
  assert.ok(result.analysis.findings.some(f => f.ruleId === 'S4BLE-K8S-005'));
});

test('NetworkPolicy empty and expression selectors reflect the selected workloads', async () => {
  const pods = ['web', 'db'].map(name => ({ apiVersion: 'v1', kind: 'Pod', metadata: { name, labels: { app: name } }, spec: { containers: [] } }));
  pods.push({ ...pods[0], metadata: { ...pods[0].metadata, namespace: 'other' } });
  const policy = { apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: { name: 'policy' }, spec: { podSelector: {} } };
  let result = await analyze({ apiVersion: 'v1', kind: 'List', items: [...pods, policy] });
  assert.equal(result.analysis.graph.links.length, 2);
  policy.spec.podSelector = { matchExpressions: [{ key: 'app', operator: 'In', values: ['web'] }] };
  result = await analyze({ apiVersion: 'v1', kind: 'List', items: [...pods, policy] });
  assert.equal(result.analysis.graph.links.length, 1);
  assert.equal(result.analysis.graph.links[0].target, 'k8s.default.Pod.web');
});

test('snapshot edges reject ambiguous aliases and missing endpoints', async () => {
  const resources = [resource('aws_vpc', {}, 'aws_vpc.main'), resource('aws_subnet', {}, 'aws_subnet.main'), resource('aws_instance', {}, 'aws_instance.app')];
  await assert.rejects(analyze({ resources, relationships: [{ source: 'main', target: 'aws_instance.app' }] }), /Ambiguous relationship endpoint/);
  await assert.rejects(analyze({ resources, relationships: [{ source: 'missing', target: 'aws_instance.app' }] }), /endpoint not found/);
  const result = await analyze({ resources, relationships: [{ source: 'aws_vpc.main', target: 'aws_instance.app' }] });
  assert.equal(result.analysis.graph.links[0].source, 'aws_vpc.main');
});

test('destroy plans never show prior resources in proposed architecture', async () => {
  const r = tfResource('aws_db_instance.main', { storage_encrypted: false });
  const result = await reviewRequest({ text: JSON.stringify({ format_version: '1.0', planned_values: {}, prior_state: { values: { root_module: { resources: [r] } } }, resource_changes: [{ ...r, change: { actions: ['delete'], before: r.values, after: null } }] }) });
  assert.equal(result.analysis.resources.length, 0);
  assert.equal(result.review.counts.delete, 1);
  assert.equal(result.review.baselineResources.length, 1);
});


test('literal Terraform resource names do not create architecture dependencies', async () => {
  const content = JSON.stringify({ resource: { aws_vpc: { main: {} }, aws_instance: { app: { description: 'aws_vpc.main', tags: { Name: '$${aws_vpc.main.id}' } } } } });
  let result = await analyzeRequest({ files: [{ name: 'main.tf.json', content }] });
  assert.equal(result.analysis.graph.links.length, 0);
  const doc = JSON.parse(content);
  doc.resource.aws_instance.app.depends_on = ['aws_vpc.main'];
  result = await analyzeRequest({ files: [{ name: 'main.tf.json', content: JSON.stringify(doc) }] });
  assert.equal(result.analysis.graph.links.length, 1);
});
