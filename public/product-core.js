// Shared, deterministic helpers used by the product UI and regression tests.
export const lessons = [
  { id: 'network', title: 'Networks & public access', categories: ['network', 'security'], keywords: 'vpc subnet firewall nsg security group public ip cidr routing',
    explanation: 'A virtual network groups cloud resources. Subnets divide its address space; routes choose traffic paths; firewall rules control permitted traffic. A public IP is only one part of the path.',
    services: 'AWS VPC / security groups · Azure VNet / NSG · Google Cloud VPC / firewall',
    misconception: 'An open rule or public IP is evidence of a configuration, not proof that an application is reachable.',
    checks: ['Trace the attached interface, subnet route, and firewall rule together.', 'Limit administration and database ports to intended sources.', 'Verify listening services and effective access in the live environment.'],
    source: 'https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html', sourceLabel: 'AWS: security group rules' },
  { id: 'compute', title: 'Instances & scaling', categories: ['compute'], keywords: 'vm ec2 cpu memory size autoscaling replicas utilization cost',
    explanation: 'Instances provide compute capacity for your application. A size describes allocated capacity; scaling changes how many instances or replicas run. Imported configuration does not tell you actual CPU or memory use.',
    services: 'Amazon EC2 · Azure Virtual Machines · Google Compute Engine',
    misconception: 'A larger instance is not automatically a faster or more resilient application.',
    checks: ['Inspect the declared instance size and scaling limits.', 'Measure workload utilization and latency before changing size.', 'Check whether replicas and failure domains meet availability needs.'],
    source: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-benefits.html', sourceLabel: 'AWS: Auto Scaling concepts' },
  { id: 'data', title: 'Databases, backups & availability', categories: ['data', 'storage'], keywords: 'rds sql backup retention restore encryption multi az recovery rpo rto',
    explanation: 'Encryption protects stored data. Backups support recovery from loss or mistakes. High availability helps a service survive failures. These controls solve different problems and should be reviewed separately.',
    services: 'Amazon RDS · Azure SQL · Google Cloud SQL',
    misconception: 'Replication and high availability do not replace tested backups.',
    checks: ['Review retention against how much data you can afford to lose (RPO).', 'Test restoration against how long you can afford to be offline (RTO).', 'Review encryption keys, public addressing, and deletion safeguards.'],
    source: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html', sourceLabel: 'AWS: database backups' },
  { id: 'identity', title: 'Identity & least privilege', categories: ['security'], keywords: 'iam role policy permission principal action resource wildcard access',
    explanation: 'An identity policy describes actions an identity may perform on resources, sometimes with conditions. Effective permission also depends on other applicable policies and explicit denies.',
    services: 'AWS IAM · Microsoft Entra ID / Azure RBAC · Google Cloud IAM',
    misconception: 'Resource: "*" alone does not prove administrator access. Some actions require it; the action and policy context matter.',
    checks: ['Identify the principal, allowed actions, resources, and conditions.', 'Review broad action wildcards and trust relationships.', 'Validate effective permissions with provider tools and organization policy.'],
    source: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html', sourceLabel: 'AWS: policy evaluation' },
  { id: 'containers', title: 'Containers & Kubernetes', categories: ['compute', 'security'], provider: 'Kubernetes', keywords: 'pod deployment cronjob service selector root privileged secret container',
    explanation: 'A Pod runs containers. Controllers such as Deployments and CronJobs create Pods. Services select Pods by labels. A container security context declares privileges and isolation settings.',
    services: 'Kubernetes · Amazon EKS · Azure AKS · Google GKE',
    misconception: 'A container is not automatically an isolation boundary when privileged mode or host namespaces are enabled.',
    checks: ['Review container and Pod security contexts, including scheduled jobs.', 'Match Service selectors to Pod-template labels in the same namespace.', 'Treat Secret values as sensitive: base64 is encoding, not encryption.'],
    source: 'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/', sourceLabel: 'Kubernetes: security contexts' },
  { id: 'evidence', title: 'Plans, state & evidence', categories: [], keywords: 'terraform plan state drift score coverage unknown source configuration',
    explanation: 'Source files describe intent. A Terraform plan describes proposed changes and known planned values. State records a snapshot. None alone proves the current behavior of your live cloud.',
    services: 'Terraform plan / state · CloudFormation templates · Kubernetes manifests',
    misconception: 'No detected findings does not mean all controls passed. Rule coverage and unknown values still matter.',
    checks: ['Prefer terraform show -json output for evaluated Terraform values.', 'Read parser diagnostics and rule coverage alongside the score.', 'Use runtime checks to verify drift, connectivity, and effective permissions.'],
    source: 'https://developer.hashicorp.com/terraform/internals/json-format', sourceLabel: 'HashiCorp: plan and state JSON' }
];

export function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

export function reviewKey(workspace, finding) {
  // Exact evidence is part of the key: changed evidence must be reviewed again.
  return stable([workspace.workspace, workspace.sourceType, (workspace.resources || []).map(r => r.id).sort(), finding.ruleId, finding.resource, finding.evidence]);
}

export function matchingResources(lesson, resources) {
  if (lesson.id === 'identity') return resources.filter(r => /iam|role|policy|service_account|serviceaccount/i.test(r.type) && !/security_group|firewall|network_security/i.test(r.type));
  if (lesson.id === 'network') return resources.filter(r => r.category === 'network' || /security_group|securitygroup|firewall|network_security/i.test(r.type));
  return resources.filter(r => (!lesson.provider || r.provider === lesson.provider) && lesson.categories.includes(r.category));
}

export function filterInventory(resources, findings, filters = {}) {
  const ids = new Set(findings.map(f => f.resource));
  const search = (filters.search || '').trim().toLowerCase();
  return resources.filter(r => (!filters.provider || filters.provider === 'all' || filters.provider === r.provider)
    && (!filters.category || filters.category === 'all' || filters.category === r.category)
    && (filters.risk !== 'findings' || ids.has(r.id)) && (filters.risk !== 'none' || !ids.has(r.id))
    && (!search || [r.id, r.name, r.type, r.provider, JSON.stringify(r.attributes?.tags || r.attributes?.Tags || {}), JSON.stringify(r.attributes?.metadata?.labels || {})].join(' ').toLowerCase().includes(search)));
}

const scalar = value => ['string', 'number', 'boolean'].includes(typeof value) && value !== '' ? String(value) : null;
export function resourceFacts(resource) {
  const a = resource.attributes || {};
  const size = [a.instance_type, a.instance_class, a.machine_type, a.size, a.vm_size, a.InstanceType, a.DBInstanceClass, a.hardware_profile?.vm_size].map(scalar).find(Boolean);
  const location = [a.region, a.location, a.zone, a.availability_zone, a.AvailabilityZone, a.metadata?.namespace].map(scalar).find(Boolean);
  return { size: size || 'Not supplied', location: location || 'Not supplied' };
}

export function csvCell(value) {
  let text = String(value ?? '');
  // Prevent spreadsheet formula execution, including tab/whitespace prefixes.
  if (/^[\s]*[=+@-]|^[\t\r\n]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}
export function inventoryCsv(resources, findings) {
  return [['Resource ID', 'Name', 'Type', 'Provider', 'Category', 'Declared size', 'Declared location / namespace', 'Detected findings'],
    ...resources.map(r => [r.id, r.name, r.type, r.provider, r.category, resourceFacts(r).size, resourceFacts(r).location, findings.filter(f => f.resource === r.id).length])]
    .map(row => row.map(csvCell).join(',')).join('\r\n');
}

export function practiceExample(provider = 'aws', restricted = false) {
  const source = restricted ? '10.20.0.0/16' : '0.0.0.0/0';
  let document;
  let description;
  if (provider === 'aws') {
    document = { workspace: 'Practice · AWS application', resources: [
      { id: 'aws_vpc.practice', type: 'aws_vpc', name: 'practice-vpc', attributes: { cidr_block: '10.20.0.0/16' } },
      { id: 'aws_security_group.admin', type: 'aws_security_group', name: 'admin-access', attributes: { ingress: [{ protocol: 'tcp', from_port: 22, to_port: 22, cidr_blocks: [source] }] } },
      { id: 'aws_instance.app', type: 'aws_instance', name: 'app-server', attributes: { instance_type: 't3.small', availability_zone: 'us-east-1a', associate_public_ip_address: !restricted, tags: { Environment: 'practice', Owner: 'platform' } } },
      { id: 'aws_db_instance.app', type: 'aws_db_instance', name: 'app-database', attributes: { instance_class: 'db.t3.micro', publicly_accessible: !restricted, storage_encrypted: restricted, backup_retention_period: restricted ? 7 : 0 } }
    ], relationships: [
      { source: 'aws_vpc.practice', target: 'aws_instance.app', label: 'Sample network membership' },
      { source: 'aws_security_group.admin', target: 'aws_instance.app', label: 'Sample security group attachment' }
    ] };
    description = 'Compare public SSH, public addressing, encryption, and backup retention. The restricted example uses a fictional private source range; it still needs a valid access path and a restore test.';
  } else if (provider === 'azure') {
    document = { workspace: 'Practice · Azure access', resources: [{ id: 'azurerm_network_security_rule.admin', type: 'azurerm_network_security_rule', name: 'admin-access', attributes: { direction: 'Inbound', access: 'Allow', protocol: 'Tcp', priority: 100, source_address_prefix: source, destination_port_range: '3389', destination_address_prefix: '*' } }] };
    description = 'Compare an internet-wide RDP source with a fictional private source range. A declared allow rule does not account for higher-priority rules or prove effective reachability.';
  } else if (provider === 'gcp') {
    document = { workspace: 'Practice · Google Cloud firewall', resources: [{ id: 'google_compute_firewall.admin', type: 'google_compute_firewall', name: 'admin-access', attributes: { direction: 'INGRESS', disabled: false, source_ranges: [source], allow: [{ protocol: 'tcp', ports: ['22'] }] } }] };
    description = 'Compare SSH from the entire internet with a fictional private source range. Firewall targets, priorities, routes, and listening services still need verification.';
  } else {
    document = { apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: 'practice-app', namespace: 'practice' }, spec: { replicas: 2, selector: { matchLabels: { app: 'practice' } }, template: { metadata: { labels: { app: 'practice' } }, spec: { containers: [{ name: 'app', image: 'example.invalid/practice:v1', securityContext: { privileged: !restricted, allowPrivilegeEscalation: !restricted, runAsNonRoot: restricted, runAsUser: restricted ? 1000 : 0, capabilities: restricted ? { drop: ['ALL'] } : { add: ['SYS_ADMIN'] }, seccompProfile: { type: restricted ? 'RuntimeDefault' : 'Unconfined' } } }] } } } };
    description = 'Compare explicit container privileges with a more restricted security context. The example image is fictional; real workloads must support the chosen UID and privileges.';
  }
  return { text: JSON.stringify(document, null, 2), filename: `practice-${provider}-${restricted ? 'restricted' : 'review'}.json`, description };
}
