import yaml from 'js-yaml';
import { parse as parseHcl } from '@cdktf/hcl2json';

const SEVERITY_WEIGHT = { critical: 20, high: 10, medium: 5, low: 2 };
const CONFIDENCE_WEIGHT = { confirmed: 1, high: 0.9, medium: 0.7, low: 0.45, inferred: 0.35 };
const SENSITIVE_PORTS = new Set([22, 3389, 3306, 5432, 6379, 9200, 27017]);

const CATEGORY_META = {
  network: { label: 'Network Edge', order: 1 },
  security: { label: 'Identity & Security', order: 2 },
  compute: { label: 'Compute Runtime', order: 3 },
  data: { label: 'Data Layer', order: 4 },
  storage: { label: 'Storage & Backup', order: 5 },
  observability: { label: 'Observability', order: 6 },
  other: { label: 'Other Resources', order: 7 }
};

export async function analyzeRequest(body) {
  const text = String(body.text || '');
  const files = normalizeFiles(body.files, text, body.filename);
  if (files.length > 100) throw new Error('A maximum of 100 files can be analyzed in one request.');
  const totalBytes = files.reduce((sum, file) => sum + Buffer.byteLength(file.content, 'utf8'), 0);
  if (totalBytes > 7_000_000) throw new Error('The submitted source exceeds the 7 MB analysis limit. Split the workspace or use Terraform plan JSON.');
  if (files.some(file => file.content.includes('\0'))) throw new Error('Binary input is not supported by this endpoint. Convert Terraform plans to JSON with terraform show -json.');
  const explicitType = body.explicitType || 'auto';
  const parsed = await parseInfrastructure({ text, files, explicitType });
  return finalizeAnalysis(parsed, { includeInferred: body.includeInferred === true });
}

export async function reviewRequest(body) {
  const result = await analyzeRequest(body);
  const baselineResources = Array.isArray(body.baseline?.resources) ? body.baseline.resources : [];
  const planChanges = result.workspace.changes || [];
  const diffs = planChanges.length ? planChanges : buildResourceDiffs(baselineResources, result.workspace.resources);
  const counts = diffs.reduce((acc, diff) => {
    const key = diff.action === 'replace' ? 'change' : diff.action;
    if (key in acc) acc[key] += 1;
    return acc;
  }, { add: 0, change: 0, delete: 0 });
  const riskScore = calculatePrRisk(result.analysis.findings, diffs);
  const decision = approvalDecision(riskScore, result.analysis.findings, diffs);
  return { ...result, review: { diffs, counts, riskScore, decision } };
}

function normalizeFiles(files, text, filename) {
  if (Array.isArray(files) && files.length) {
    return files.map((file, index) => ({
      name: String(file?.name || `input-${index + 1}.txt`),
      content: String(file?.content ?? '')
    }));
  }
  return text ? [{ name: filename || 'pasted-input.txt', content: text }] : [];
}

async function parseInfrastructure({ text, files, explicitType }) {
  if (!text.trim() && !files.some(file => file.content.trim())) {
    return emptyWorkspace();
  }
  const type = explicitType === 'auto' ? detectType(text, files) : explicitType;
  if (type === 'json') return parseJsonDocument(text || files[0]?.content || '');
  if (type === 'yaml') return parseYamlDocuments(text || files[0]?.content || '', files);
  if (type === 'terraform') return parseTerraformSource(files);
  throw new Error(`Unsupported input type: ${type}`);
}

function detectType(text, files) {
  const primary = String(text || files[0]?.content || '').trim();
  const names = files.map(file => file.name.toLowerCase());
  if (names.length && names.every(name => name.endsWith('.tf') || name.endsWith('.tf.json'))) return 'terraform';
  if (primary.startsWith('{') || primary.startsWith('[')) return 'json';
  if (names.some(name => /\.ya?ml$/.test(name))) return 'yaml';
  if (/^\s*(apiVersion|kind|Resources|AWSTemplateFormatVersion|workspace|resources)\s*:/m.test(primary)) return 'yaml';
  if (/\b(resource|module|data|terraform|provider|variable|locals|output)\s+(?:"|\{)/.test(primary)) return 'terraform';
  if (/Terraform will perform the following actions|Plan:\s*\d+\s+to add/i.test(primary)) {
    throw new Error('Human-readable Terraform plan output is not a stable machine interface. Generate an authoritative plan JSON with: terraform show -json tfplan > plan.json');
  }
  return 'terraform';
}

function emptyWorkspace() {
  return {
    workspace: 'Empty workspace', sourceType: 'empty', analysisMode: 'empty', authoritative: false,
    importedAt: new Date().toISOString(), resources: [], explicitLinks: [], inferredLinks: [], diagnostics: [], changes: []
  };
}

function parseJsonDocument(text) {
  let doc;
  try { doc = JSON.parse(text); } catch (error) { throw new Error(`JSON parsing failed: ${error.message}`); }
  if (isTerraformShowJson(doc)) return parseTerraformShowJson(doc);
  if (isCloudFormation(doc)) return parseCloudFormation(doc, 'json');
  if (isKubernetesObject(doc)) return parseKubernetesDocuments([doc], 'json');
  if (Array.isArray(doc?.items) && doc.items.every(isKubernetesObject)) return parseKubernetesDocuments(doc.items, 'json');
  if (Array.isArray(doc) || Array.isArray(doc?.resources)) return parseNormalizedSnapshot(doc, 'json');
  throw new Error('JSON is valid, but its schema is not recognized. Supported JSON: terraform show -json plan/state, CloudFormation, Kubernetes objects/lists, or Sable normalized snapshots.');
}

function isTerraformShowJson(doc) {
  return Boolean(doc && typeof doc === 'object' && doc.format_version && (doc.planned_values || doc.values || doc.resource_changes || doc.configuration));
}

function parseTerraformShowJson(doc) {
  validateTerraformFormatVersion(doc.format_version);
  const resources = [];
  const diagnostics = [];
  const changes = [];
  const changeMap = new Map();
  for (const change of doc.resource_changes || []) {
    const actions = change?.change?.actions || [];
    const action = normalizeTerraformActions(actions);
    const entry = {
      action,
      resource: change.address,
      type: change.type,
      description: `Terraform plan actions: ${actions.join(', ') || 'no-op'}.`,
      before: redactSensitive(change?.change?.before, change?.change?.before_sensitive),
      after: redactSensitive(change?.change?.after, change?.change?.after_sensitive)
    };
    if (action !== 'present') changes.push(entry);
    changeMap.set(change.address, entry);
  }

  const root = doc.planned_values?.root_module || doc.values?.root_module || doc.prior_state?.values?.root_module;
  if (root) collectTerraformValueModule(root, resources, changeMap);

  const explicitLinks = collectTerraformConfigurationLinks(doc.configuration, resources);
  const mode = doc.planned_values || doc.resource_changes ? 'terraform-plan-json' : 'terraform-state-json';
  diagnostics.push({
    level: 'info', code: 'terraform-json-authoritative',
    message: 'Terraform machine-readable JSON detected. Resource values and declared expression references are treated as authoritative for this Terraform workspace.'
  });
  if (doc.planned_values) {
    diagnostics.push({
      level: 'warning', code: 'terraform-sensitive-json',
      message: 'Terraform show -json can contain sensitive values. Sable redacts fields marked sensitive by Terraform before returning analysis data.'
    });
  }
  return {
    workspace: doc.terraform_version ? `Terraform ${doc.terraform_version} workspace` : 'Terraform workspace',
    sourceType: 'terraform-json', analysisMode: mode, authoritative: true,
    importedAt: new Date().toISOString(), resources: dedupeById(resources), explicitLinks, inferredLinks: [], diagnostics, changes,
    scope: 'terraform-workspace'
  };
}

function validateTerraformFormatVersion(version) {
  const major = Number(String(version || '0').split('.')[0]);
  if (major !== 1) throw new Error(`Unsupported Terraform JSON format_version ${version}. Sable supports major version 1.x.`);
}

function collectTerraformValueModule(module, resources, changeMap) {
  for (const resource of module.resources || []) {
    const address = resource.address || `${resource.type}.${resource.name}`;
    const change = changeMap.get(address);
    const values = redactSensitive(resource.values || change?.after || {}, resource.sensitive_values || change?.after_sensitive);
    resources.push(normalizeResource({
      id: address, address, moduleAddress: resource.module_address || module.address || null, mode: resource.mode || 'managed',
      type: resource.type, name: resource.name || nameFromAddress(address), provider: providerFromType(resource.type),
      category: classifyType(resource.type), attributes: values, action: change?.action || 'present',
      source: { kind: 'terraform-show-json', address }
    }));
  }
  for (const child of module.child_modules || []) collectTerraformValueModule(child, resources, changeMap);
}

function collectTerraformConfigurationLinks(configuration, resources) {
  if (!configuration?.root_module) return [];
  const ids = new Set(resources.map(resource => resource.id));
  const links = new Map();
  const add = (source, target, evidence) => {
    const resolvedSource = resolveTerraformResourceAddress(source, ids, target);
    const resolvedTarget = resolveTerraformResourceAddress(target, ids, target);
    if (!resolvedSource || !resolvedTarget || resolvedSource === resolvedTarget) return;
    const key = `${resolvedSource}=>${resolvedTarget}`;
    if (!links.has(key)) links.set(key, {
      source: resolvedSource, target: resolvedTarget, label: 'declared Terraform reference', confidence: 'confirmed', evidence
    });
  };
  const resolveBoundRefs = (refs, inputBindings) => refs.flatMap(ref => {
    const match = /^var\.([A-Za-z0-9_-]+)/.exec(ref);
    if (!match) return [ref];
    return inputBindings[match[1]] || [];
  });
  const walk = (mod, modulePrefix = '', inputBindings = {}) => {
    for (const resource of mod.resources || []) {
      const target = resource.address ? qualifyTerraformAddress(resource.address, modulePrefix) : qualifyTerraformAddress(`${resource.type}.${resource.name}`, modulePrefix);
      const refs = [];
      scanExpressionReferences(resource.expressions || {}, ref => refs.push(ref));
      for (const ref of resolveBoundRefs(refs, inputBindings)) add(ref, target, { source: 'configuration.expressions', reference: ref });
      for (const dep of resource.depends_on || []) add(dep, target, { source: 'depends_on', reference: dep });
    }
    for (const [callName, call] of Object.entries(mod.module_calls || {})) {
      const prefix = modulePrefix ? `${modulePrefix}.module.${callName}` : `module.${callName}`;
      const childBindings = {};
      for (const [argument, expression] of Object.entries(call?.expressions || {})) {
        const refs = [];
        scanExpressionReferences(expression, ref => refs.push(ref));
        childBindings[argument] = resolveBoundRefs(refs, inputBindings);
      }
      if (call?.module) walk(call.module, prefix, childBindings);
    }
  };
  walk(configuration.root_module, '', {});
  return Array.from(links.values());
}

function scanExpressionReferences(value, callback) {
  if (!value) return;
  if (Array.isArray(value)) return value.forEach(item => scanExpressionReferences(item, callback));
  if (typeof value !== 'object') return;
  if (Array.isArray(value.references)) value.references.forEach(callback);
  Object.values(value).forEach(item => scanExpressionReferences(item, callback));
}

function qualifyTerraformAddress(address, modulePrefix) {
  if (!modulePrefix || String(address).startsWith('module.')) return String(address);
  return `${modulePrefix}.${address}`;
}

function resolveTerraformResourceAddress(ref, ids, targetAddress = '') {
  const clean = String(ref || '').replace(/^\$\{?|\}?$/g, '');
  if (!clean || /^(var|local|path|terraform|data)\./.test(clean)) return null;
  const targetModule = String(targetAddress).split('.').slice(0, -2).join('.');
  const candidates = Array.from(ids).sort((a, b) => b.length - a.length);
  for (const id of candidates) {
    if (clean === id || clean.startsWith(`${id}.`) || clean.startsWith(`${id}[`) || id.startsWith(`${clean}[`)) return id;
  }
  if (targetModule.startsWith('module.') && !clean.startsWith('module.')) {
    const prefixed = `${targetModule}.${clean}`;
    for (const id of candidates) if (prefixed === id || prefixed.startsWith(`${id}.`) || prefixed.startsWith(`${id}[`) || id.startsWith(`${prefixed}[`)) return id;
  }
  return null;
}

async function parseTerraformSource(files) {
  if (!files.length) throw new Error('No Terraform source was provided.');
  const resources = [];
  const explicitLinks = [];
  const diagnostics = [];
  for (const file of files) {
    if (!file.content.trim()) continue;
    let doc;
    try { doc = await parseHcl(file.name || 'input.tf', file.content); }
    catch (error) { throw new Error(`Terraform HCL parsing failed in ${file.name}: ${error.message}`); }
    collectHclResources(doc, file.name, resources);
  }
  const duplicateIds = resources.map(resource => resource.id).filter((id, index, all) => all.indexOf(id) !== index);
  if (duplicateIds.length) throw new Error(`Duplicate Terraform resource declarations detected: ${Array.from(new Set(duplicateIds)).join(', ')}`);
  const deduped = dedupeById(resources);
  const ids = new Set(deduped.map(resource => resource.id));
  for (const resource of deduped) {
    const refs = extractTerraformRefs(resource.attributes);
    for (const ref of refs) {
      const source = resolveTerraformResourceAddress(ref, ids, resource.id);
      if (source && source !== resource.id) explicitLinks.push({
        source, target: resource.id, label: 'declared HCL reference', confidence: 'confirmed',
        evidence: { source: resource.source?.file || 'Terraform source', reference: ref }
      });
    }
  }
  diagnostics.push({
    level: 'warning', code: 'terraform-static-mode',
    message: 'Raw .tf source is parsed with an HCL2 parser, but expressions, variables, for_each/count instances, provider defaults, remote modules, and runtime unknowns are not fully evaluated. For authoritative values and resource instances, import terraform show -json output from a plan or state.'
  });
  if (containsModuleBlocks(files)) diagnostics.push({
    level: 'warning', code: 'terraform-modules-unresolved',
    message: 'Module calls were detected. Source-only analysis does not claim resources inside remote or unprovided module directories. Include their .tf files or analyze plan JSON.'
  });
  return {
    workspace: files.length > 1 ? 'Terraform source workspace' : (files[0]?.name || 'Terraform source'),
    sourceType: 'terraform-hcl', analysisMode: 'terraform-static-source', authoritative: false,
    importedAt: new Date().toISOString(), resources: deduped, explicitLinks: dedupeLinks(explicitLinks), inferredLinks: [], diagnostics, changes: [], scope: 'provided-source-files'
  };
}

function collectHclResources(doc, fileName, resources) {
  const resourceRoot = doc?.resource || {};
  for (const [type, names] of Object.entries(resourceRoot)) {
    for (const [name, blocks] of Object.entries(names || {})) {
      const entries = Array.isArray(blocks) ? blocks : [blocks];
      entries.forEach((attrs, index) => {
        const id = `${type}.${name}${entries.length > 1 ? `[${index}]` : ''}`;
        resources.push(normalizeResource({
          id, address: id, type, name, provider: providerFromType(type), category: classifyType(type),
          attributes: attrs || {}, action: 'present', source: { kind: 'terraform-hcl', file: fileName, address: id }
        }));
      });
    }
  }
}

function containsModuleBlocks(files) {
  return files.some(file => /(^|\n)\s*module\s+"/m.test(file.content));
}

function extractTerraformRefs(value) {
  const refs = new Set();
  const visit = item => {
    if (item == null) return;
    if (typeof item === 'string') {
      const regex = /(?:module\.[A-Za-z0-9_-]+\.)*(?:aws|azurerm|google|kubernetes)_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\[[^\]]+\])?/g;
      for (const match of item.matchAll(regex)) refs.add(match[0]);
      return;
    }
    if (Array.isArray(item)) return item.forEach(visit);
    if (typeof item === 'object') Object.values(item).forEach(visit);
  };
  visit(value);
  return Array.from(refs);
}

function cloudFormationSchema() {
  const scalarTags = ['!Ref', '!Sub', '!GetAtt', '!ImportValue', '!GetAZs', '!Base64', '!Condition'];
  const seqTags = ['!Sub', '!GetAtt', '!Join', '!Select', '!Split', '!FindInMap', '!If', '!Equals', '!And', '!Or', '!Not', '!Cidr'];
  const scalarTypes = scalarTags.map(tag => new yaml.Type(tag, { kind: 'scalar', construct: data => ({ [tag.slice(1)]: data }) }));
  const seqTypes = seqTags.map(tag => new yaml.Type(tag, { kind: 'sequence', construct: data => ({ [tag.slice(1)]: data }) }));
  return yaml.DEFAULT_SCHEMA.extend([...scalarTypes, ...seqTypes]);
}

function parseYamlDocuments(text, files) {
  const docs = [];
  const sources = Array.isArray(files) && files.length > 1 ? files : [{ name: files?.[0]?.name || 'input.yaml', content: text }];
  try {
    for (const source of sources) {
      yaml.loadAll(source.content, doc => { if (doc != null) docs.push(doc); }, { schema: cloudFormationSchema() });
    }
  } catch (error) {
    throw new Error(`YAML parsing failed: ${error.message}`);
  }
  if (!docs.length) return emptyWorkspace();
  if (docs.length === 1 && isCloudFormation(docs[0])) return parseCloudFormation(docs[0], 'yaml');
  if (docs.every(isKubernetesObject)) return parseKubernetesDocuments(docs, 'yaml');
  if (docs.length === 1 && (Array.isArray(docs[0]) || Array.isArray(docs[0]?.resources))) return parseNormalizedSnapshot(docs[0], 'yaml');
  throw new Error('YAML is valid, but its schema is not recognized. Supported YAML: one CloudFormation template, Kubernetes multi-document/manifold files, or one Sable normalized snapshot.');
}

function isCloudFormation(doc) {
  return Boolean(doc && typeof doc === 'object' && doc.Resources && typeof doc.Resources === 'object');
}

function parseCloudFormation(doc, sourceType) {
  const resources = [];
  const logicalToId = new Map();
  for (const [logicalId, definition] of Object.entries(doc.Resources || {})) {
    const type = definition?.Type || 'AWS::Unknown::Resource';
    const id = `cfn.${logicalId}`;
    logicalToId.set(logicalId, id);
    resources.push(normalizeResource({
      id, address: logicalId, type, name: logicalId, provider: 'AWS', category: classifyType(type),
      attributes: definition?.Properties || {}, source: { kind: `cloudformation-${sourceType}`, logicalId }, action: 'present'
    }));
  }
  const links = [];
  for (const [logicalId, definition] of Object.entries(doc.Resources || {})) {
    const target = logicalToId.get(logicalId);
    const refs = new Set();
    collectCloudFormationRefs(definition?.Properties, refs);
    const depends = definition?.DependsOn;
    for (const dep of Array.isArray(depends) ? depends : (depends ? [depends] : [])) refs.add(dep);
    for (const ref of refs) {
      const source = logicalToId.get(ref);
      if (source && source !== target) links.push({ source, target, label: 'CloudFormation reference', confidence: 'confirmed', evidence: { logicalId, reference: ref } });
    }
  }
  return {
    workspace: doc.Description || 'CloudFormation stack', sourceType: `cloudformation-${sourceType}`,
    analysisMode: 'declarative-template', authoritative: true, importedAt: new Date().toISOString(),
    resources, explicitLinks: dedupeLinks(links), inferredLinks: [], diagnostics: [{ level: 'info', code: 'cloudformation-template', message: 'CloudFormation template parsed with intrinsic reference tracking. Runtime values not present in the template are not invented.' }], changes: [], scope: 'provided-template'
  };
}

function collectCloudFormationRefs(value, refs) {
  if (value == null) return;
  if (Array.isArray(value)) return value.forEach(item => collectCloudFormationRefs(item, refs));
  if (typeof value === 'string') {
    for (const match of value.matchAll(/\$\{([A-Za-z0-9]+)(?:\.[^}]+)?\}/g)) refs.add(match[1]);
    return;
  }
  if (typeof value !== 'object') return;
  if (typeof value.Ref === 'string') refs.add(value.Ref);
  const getAtt = value['Fn::GetAtt'] || value.GetAtt;
  if (typeof getAtt === 'string') refs.add(getAtt.split('.')[0]);
  if (Array.isArray(getAtt) && typeof getAtt[0] === 'string') refs.add(getAtt[0]);
  Object.values(value).forEach(item => collectCloudFormationRefs(item, refs));
}

function isKubernetesObject(doc) {
  return Boolean(doc && typeof doc === 'object' && typeof doc.apiVersion === 'string' && typeof doc.kind === 'string');
}

function parseKubernetesDocuments(docs, sourceType) {
  const expanded = [];
  for (const doc of docs) {
    if (doc.kind === 'List' && Array.isArray(doc.items)) expanded.push(...doc.items.filter(isKubernetesObject));
    else expanded.push(doc);
  }
  const resources = expanded.map(doc => {
    const namespace = doc.metadata?.namespace || 'default';
    const name = doc.metadata?.name || 'unnamed';
    const type = `kubernetes_${snakeCase(doc.kind)}`;
    return normalizeResource({
      id: `k8s.${namespace}.${doc.kind}.${name}`, address: `${namespace}/${doc.kind}/${name}`, type, name,
      provider: 'Kubernetes', category: classifyType(type), attributes: doc, source: { kind: `kubernetes-${sourceType}`, namespace, apiVersion: doc.apiVersion }, action: 'present'
    });
  });
  const links = buildKubernetesLinks(resources);
  return {
    workspace: 'Kubernetes manifests', sourceType: `kubernetes-${sourceType}`, analysisMode: 'declarative-manifest', authoritative: true,
    importedAt: new Date().toISOString(), resources, explicitLinks: links, inferredLinks: [], diagnostics: [{ level: 'info', code: 'kubernetes-manifest', message: 'Kubernetes manifests parsed structurally. Service selectors, workload references, ingress backends, volumes, and service accounts are linked when declared.' }], changes: [], scope: 'provided-manifests'
  };
}

function buildKubernetesLinks(resources) {
  const links = [];
  const byKindNameNs = new Map();
  for (const r of resources) {
    const doc = r.attributes || {};
    byKindNameNs.set(`${doc.kind}:${doc.metadata?.namespace || 'default'}:${doc.metadata?.name}`, r.id);
  }
  const workloads = resources.filter(r => /deployment|stateful_set|daemon_set|pod|job|cron_job/.test(r.type));
  for (const service of resources.filter(r => r.type === 'kubernetes_service')) {
    const doc = service.attributes;
    const selector = doc.spec?.selector || {};
    if (Object.keys(selector).length) {
      for (const workload of workloads) {
        const wdoc = workload.attributes;
        const ns = wdoc.metadata?.namespace || 'default';
        if (ns !== (doc.metadata?.namespace || 'default')) continue;
        const labels = wdoc.spec?.template?.metadata?.labels || wdoc.metadata?.labels || {};
        if (Object.entries(selector).every(([k, v]) => labels[k] === v)) links.push({ source: service.id, target: workload.id, label: 'Service selector', confidence: 'confirmed', evidence: { selector } });
      }
    }
  }
  for (const ingress of resources.filter(r => r.type === 'kubernetes_ingress')) {
    const doc = ingress.attributes;
    const ns = doc.metadata?.namespace || 'default';
    const names = [];
    for (const rule of doc.spec?.rules || []) for (const path of rule.http?.paths || []) {
      const name = path.backend?.service?.name || path.backend?.serviceName;
      if (name) names.push(name);
    }
    const defaultName = doc.spec?.defaultBackend?.service?.name || doc.spec?.backend?.serviceName;
    if (defaultName) names.push(defaultName);
    for (const name of names) {
      const target = byKindNameNs.get(`Service:${ns}:${name}`);
      if (target) links.push({ source: ingress.id, target, label: 'Ingress backend', confidence: 'confirmed', evidence: { service: name } });
    }
  }
  for (const workload of workloads) {
    const doc = workload.attributes;
    const ns = doc.metadata?.namespace || 'default';
    const spec = doc.spec?.template?.spec || doc.spec || {};
    if (spec.serviceAccountName) {
      const target = byKindNameNs.get(`ServiceAccount:${ns}:${spec.serviceAccountName}`);
      if (target) links.push({ source: target, target: workload.id, label: 'Service account', confidence: 'confirmed', evidence: { serviceAccountName: spec.serviceAccountName } });
    }
    for (const volume of spec.volumes || []) {
      const candidates = [
        ['Secret', volume.secret?.secretName], ['ConfigMap', volume.configMap?.name], ['PersistentVolumeClaim', volume.persistentVolumeClaim?.claimName]
      ];
      for (const [kind, name] of candidates) {
        const target = name ? byKindNameNs.get(`${kind}:${ns}:${name}`) : null;
        if (target) links.push({ source: target, target: workload.id, label: 'Volume/config reference', confidence: 'confirmed', evidence: { kind, name } });
      }
    }
  }
  return dedupeLinks(links);
}

function parseNormalizedSnapshot(doc, sourceType) {
  const root = Array.isArray(doc) ? { workspace: 'Imported snapshot', resources: doc } : doc;
  const resources = (root.resources || []).map((resource, index) => normalizeResource({ ...resource, id: resource.id || resource.address || `${resource.type || 'unknown'}.${resource.name || index}` }));
  const idMap = new Map();
  for (const r of resources) {
    idMap.set(r.id, r.id);
    idMap.set(`${r.type}.${r.name}`, r.id);
    idMap.set(r.name, r.id);
  }
  const links = (root.relationships || root.links || []).map(link => ({
    source: idMap.get(link.source) || link.source,
    target: idMap.get(link.target) || link.target,
    label: link.label || 'declared relationship', confidence: link.confidence || 'confirmed', evidence: link.evidence || { source: 'snapshot' }
  })).filter(link => idMap.has(link.source) || resources.some(r => r.id === link.source)).filter(link => idMap.has(link.target) || resources.some(r => r.id === link.target));
  return {
    workspace: root.workspace || root.name || 'Imported snapshot', sourceType: `snapshot-${sourceType}`, analysisMode: 'normalized-snapshot', authoritative: true,
    importedAt: new Date().toISOString(), resources, explicitLinks: dedupeLinks(links), inferredLinks: [], diagnostics: [{ level: 'info', code: 'normalized-snapshot', message: 'Normalized snapshot resources are treated as declared facts. Only supplied relationships are shown as confirmed.' }], changes: [], scope: 'provided-snapshot'
  };
}

function finalizeAnalysis(workspace, options = {}) {
  const resources = dedupeById((workspace.resources || []).map(normalizeResource));
  const findings = [];
  for (const resource of resources) findings.push(...evaluateResource(resource, resources, workspace));
  findings.push(...evaluateScopeControls(resources, workspace));
  const explicitLinks = dedupeLinks((workspace.explicitLinks || []).filter(link => hasResource(resources, link.source) && hasResource(resources, link.target)));
  const inferredLinks = options.includeInferred ? inferConservativeLinks(resources, explicitLinks) : [];
  const graph = { links: explicitLinks, inferredLinks };
  const counts = countFindings(findings);
  const score = calculatePostureScore(findings);
  const grouped = groupResources(resources, findings);
  return {
    workspace: { ...workspace, resources, explicitLinks, inferredLinks },
    analysis: {
      resources, findings: sortFindings(findings), grouped, counts, score, graph, diagnostics: workspace.diagnostics || [],
      metadata: {
        analysisMode: workspace.analysisMode,
        authoritative: Boolean(workspace.authoritative),
        scope: workspace.scope,
        providersDetected: Array.from(new Set(resources.map(resource => resource.provider))).sort(),
        relationshipPolicy: 'Confirmed edges come only from declared/imported evidence. Inferred edges are stored separately and labeled inferred.',
        scoreModel: 'Sable evidence-weighted posture score: critical 20, high 10, medium 5, low 2; reduced only when a finding is not confirmed. This is not a cloud-provider certification score.'
      }
    }
  };
}

function evaluateResource(resource, allResources, workspace) {
  const findings = [];
  if (resource.mode === 'data') return [];
  const provider = resource.provider;
  if (provider === 'AWS') findings.push(...evaluateAws(resource, allResources));
  if (provider === 'Azure') findings.push(...evaluateAzure(resource));
  if (provider === 'GCP') findings.push(...evaluateGcp(resource));
  if (provider === 'Kubernetes') findings.push(...evaluateKubernetes(resource));
  return findings.map(f => ({ ...f, sourceMode: workspace.analysisMode }));
}

function evaluateAws(resource, allResources) {
  const out = [];
  const type = resource.type.toLowerCase();
  const a = resource.attributes || {};
  if (/security_group|securitygroup|security_group_rule|security_group_ingress_rule/i.test(type)) {
    const rules = normalizeSecurityRules(a);
    for (const rule of rules) {
      const publicSource = rule.sources.some(isWorldCidr);
      const ports = expandPortRange(rule.fromPort, rule.toPort);
      const sensitive = ports.some(port => SENSITIVE_PORTS.has(port));
      if (publicSource && sensitive) out.push(finding('critical', 'Sensitive port exposed to the internet', resource, 'A declared ingress rule permits a sensitive administrative or database port from a world-routable CIDR.', 'Restrict the source to a private network, VPN, zero-trust access path, or tightly scoped administrative CIDR.', 'confirmed', { attribute: rule.path, value: rule }));
    }
  }
  if (/db_instance|rds|aws::rds::dbinstance/i.test(type)) {
    const publicValue = firstDefined(a.publicly_accessible, a.PubliclyAccessible);
    if (publicValue === true) out.push(finding('high', 'Public database endpoint enabled', resource, 'The database is configured to receive a publicly addressable endpoint. This does not by itself prove internet reachability because security groups and routes still apply.', 'Prefer private database endpoints unless public addressing is explicitly required, and verify network policy limits access.', 'confirmed', { attribute: 'publicly_accessible/PubliclyAccessible', value: true }));
    const encrypted = firstDefined(a.storage_encrypted, a.StorageEncrypted);
    if (encrypted === false) out.push(finding('high', 'Database storage encryption disabled', resource, 'The declared database storage encryption setting is disabled.', 'Enable provider-supported storage encryption using a managed or customer-managed key.', 'confirmed', { attribute: 'storage_encrypted/StorageEncrypted', value: false }));
    const backup = firstDefined(a.backup_retention_period, a.BackupRetentionPeriod);
    if (Number(backup) === 0) out.push(finding('high', 'Automated database backups disabled', resource, 'Backup retention is explicitly set to zero.', 'Set a retention period that meets recovery objectives and regularly test restoration.', 'confirmed', { attribute: 'backup_retention_period/BackupRetentionPeriod', value: backup }));
    const multiAz = firstDefined(a.multi_az, a.MultiAZ);
    if (multiAz === false) out.push(finding('medium', 'Multi-AZ database deployment disabled', resource, 'The database is explicitly configured without Multi-AZ high availability.', 'Enable Multi-AZ where workload availability requirements justify it.', 'confirmed', { attribute: 'multi_az/MultiAZ', value: false }));
  }
  if (/s3_bucket$|aws::s3::bucket/i.test(type)) {
    const acl = String(firstDefined(a.acl, a.AccessControl, '')).toLowerCase();
    if (/public-read|publicread|public-read-write|publicreadwrite/.test(acl)) out.push(finding('critical', 'Public bucket ACL declared', resource, 'The bucket ACL explicitly grants public access.', 'Use private ACLs and tightly scoped bucket policies or signed delivery mechanisms.', 'confirmed', { attribute: 'acl/AccessControl', value: acl }));
  }
  if (/s3_bucket_public_access_block/.test(type)) {
    const disabled = ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets'].filter(key => a[key] === false);
    if (disabled.length) out.push(finding('high', 'S3 public access block controls disabled', resource, `The following controls are explicitly false: ${disabled.join(', ')}.`, 'Enable all public-access-block controls unless a reviewed exception requires otherwise.', 'confirmed', { attribute: disabled.join(','), value: false }));
  }
  if (/iam_policy|iam_role_policy|aws::iam::policy/i.test(type)) {
    if (hasWildcardIam(a)) out.push(finding('high', 'Wildcard IAM permission detected', resource, 'The policy declares wildcard actions or resources, increasing privilege scope.', 'Scope actions and resources to the minimum required permissions and ARNs.', 'confirmed', { attribute: 'policy', value: '[policy contains wildcard]' }));
  }
  if (/ebs_volume|aws::ec2::volume/i.test(type)) {
    const encrypted = firstDefined(a.encrypted, a.Encrypted);
    if (encrypted === false) out.push(finding('medium', 'Block storage encryption disabled', resource, 'Encryption is explicitly disabled on the block storage resource.', 'Enable encryption and use an appropriate KMS key policy.', 'confirmed', { attribute: 'encrypted/Encrypted', value: false }));
  }
  if (/launch_template|instance$|aws::ec2::instance/i.test(type)) {
    const publicIp = firstDefined(a.associate_public_ip_address, a.AssociatePublicIpAddress);
    const nestedPublic = Array.isArray(a.network_interfaces) && a.network_interfaces.some(n => n?.associate_public_ip_address === true);
    if (publicIp === true || nestedPublic) out.push(finding('medium', 'Public IP assignment enabled', resource, 'The compute configuration explicitly enables a public IP address.', 'Prefer private addressing behind controlled ingress unless direct internet addressing is required.', 'confirmed', { attribute: 'associate_public_ip_address', value: true }));
  }
  if (/autoscaling_group|aws::autoscaling::autoscalinggroup/i.test(type)) {
    const max = firstDefined(a.max_size, a.MaxSize);
    if (max != null && Number(max) <= 1) out.push(finding('medium', 'Auto Scaling maximum capacity is one', resource, 'The declared maximum capacity prevents the group from running more than one instance.', 'Set capacity according to availability and scaling requirements, typically across multiple failure domains.', 'confirmed', { attribute: 'max_size/MaxSize', value: max }));
  }
  return out;
}

function evaluateAzure(resource) {
  const out = [];
  const type = resource.type.toLowerCase();
  const a = resource.attributes || {};
  if (/network_security_group|networksecuritygroups/.test(type)) {
    const rules = a.security_rule || a.security_rules || a.securityRules || [];
    for (const rule of Array.isArray(rules) ? rules : [rules]) {
      const direction = String(rule.direction || '').toLowerCase();
      const access = String(rule.access || '').toLowerCase();
      const sources = [rule.source_address_prefix, ...(rule.source_address_prefixes || [])].filter(Boolean);
      const ports = String(rule.destination_port_range || '').split(',').flatMap(parsePortToken);
      if (direction === 'inbound' && access === 'allow' && sources.some(source => source === '*' || source === '0.0.0.0/0' || source === '::/0') && ports.some(port => SENSITIVE_PORTS.has(port))) {
        out.push(finding('critical', 'Sensitive NSG port exposed publicly', resource, 'An inbound allow rule permits a sensitive port from a world-routable source.', 'Restrict the source prefix and use managed administrative access paths.', 'confirmed', { attribute: 'security_rule', value: rule }));
      }
    }
  }
  if (/storage_account/.test(type)) {
    const publicAccess = firstDefined(a.allow_nested_items_to_be_public, a.allow_blob_public_access);
    if (publicAccess === true) out.push(finding('medium', 'Blob public access capability enabled', resource, 'The storage account allows nested items or blobs to be configured for public access.', 'Disable public blob access unless it is a deliberate requirement.', 'confirmed', { attribute: 'allow_nested_items_to_be_public', value: true }));
  }
  return out;
}

function evaluateGcp(resource) {
  const out = [];
  const type = resource.type.toLowerCase();
  const a = resource.attributes || {};
  if (/compute_firewall/.test(type)) {
    const sources = a.source_ranges || [];
    const world = Array.isArray(sources) && sources.some(isWorldCidr);
    const allowed = a.allow || [];
    const ports = (Array.isArray(allowed) ? allowed : [allowed]).flatMap(rule => (rule?.ports || []).flatMap(parsePortToken));
    if (world && ports.some(port => SENSITIVE_PORTS.has(port))) out.push(finding('critical', 'Sensitive firewall port exposed publicly', resource, 'The firewall source range includes the internet and allows a sensitive port.', 'Restrict source ranges or use identity-aware administrative access.', 'confirmed', { attribute: 'source_ranges/allow', value: { sources, allowed } }));
  }
  if (/sql_database_instance/.test(type)) {
    const ipConfig = Array.isArray(a.settings) ? a.settings[0]?.ip_configuration : a.settings?.ip_configuration || a.ip_configuration;
    const ipv4 = Array.isArray(ipConfig) ? ipConfig[0]?.ipv4_enabled : ipConfig?.ipv4_enabled;
    if (ipv4 === true) out.push(finding('high', 'Cloud SQL public IPv4 enabled', resource, 'The database instance explicitly enables a public IPv4 interface. Authorized networks and IAM still determine effective access.', 'Prefer private IP where practical and tightly restrict authorized networks.', 'confirmed', { attribute: 'settings.ip_configuration.ipv4_enabled', value: true }));
  }
  return out;
}

function evaluateKubernetes(resource) {
  const out = [];
  const doc = resource.attributes || {};
  const podSpec = doc.spec?.template?.spec || (doc.kind === 'Pod' ? doc.spec : null);
  if (!podSpec) return out;
  if (podSpec.hostNetwork === true) out.push(finding('high', 'Pod uses host network namespace', resource, 'hostNetwork is explicitly enabled, reducing network isolation from the node.', 'Disable hostNetwork unless the workload has a reviewed operational requirement.', 'confirmed', { attribute: 'spec.hostNetwork', value: true }));
  const containers = [...(podSpec.containers || []), ...(podSpec.initContainers || [])];
  for (const container of containers) {
    const sc = container.securityContext || {};
    if (sc.privileged === true) out.push(finding('critical', `Privileged container: ${container.name || 'unnamed'}`, resource, 'A container explicitly requests privileged mode.', 'Remove privileged mode and grant only the specific Linux capabilities required.', 'confirmed', { attribute: `container.${container.name}.securityContext.privileged`, value: true }));
    if (sc.allowPrivilegeEscalation === true) out.push(finding('high', `Privilege escalation allowed: ${container.name || 'unnamed'}`, resource, 'The container explicitly allows privilege escalation.', 'Set allowPrivilegeEscalation to false unless a reviewed workload requires it.', 'confirmed', { attribute: `container.${container.name}.securityContext.allowPrivilegeEscalation`, value: true }));
  }
  return out;
}

function evaluateScopeControls(resources, workspace) {
  const out = [];
  if (!resources.length) return out;
  const awsResources = resources.filter(r => r.provider === 'AWS');
  if (awsResources.length && workspace.analysisMode === 'terraform-plan-json') {
    const hasTrail = awsResources.some(r => /cloudtrail/i.test(r.type));
    if (!hasTrail) out.push({
      id: makeId('scope-audit'), ruleId: 'IV-AWS-SCOPE-CLOUDTRAIL', severity: 'low', title: 'No CloudTrail resource in imported Terraform plan scope', resource: 'workspace',
      description: 'The analyzed Terraform plan does not declare a CloudTrail resource. CloudTrail may still be managed in another workspace or account-level control plane.',
      recommendation: 'Confirm organization/account audit logging exists outside this workspace or manage it explicitly here.', confidence: 'medium', evidence: { scope: workspace.scope }, sourceMode: workspace.analysisMode
    });
  }
  return out;
}

function normalizeSecurityRules(a) {
  const result = [];
  let ingress = a.ingress || a.SecurityGroupIngress || [];
  const looksLikeStandaloneRule = ['from_port', 'FromPort', 'cidr_ipv4', 'cidr_ipv6', 'CidrIp', 'CidrIpv6'].some(key => a[key] !== undefined);
  if ((!Array.isArray(ingress) || !ingress.length) && looksLikeStandaloneRule) ingress = [a];
  for (const [index, rule] of (Array.isArray(ingress) ? ingress : [ingress]).entries()) {
    if (!rule || typeof rule !== 'object') continue;
    const fromPort = Number(firstDefined(rule.from_port, rule.FromPort, 0));
    const toPort = Number(firstDefined(rule.to_port, rule.ToPort, fromPort));
    const sources = [
      ...(rule.cidr_blocks || []), ...(rule.ipv6_cidr_blocks || []),
      rule.cidr_ipv4, rule.cidr_ipv6, rule.CidrIp, rule.CidrIpv6, rule.cidr, rule.source
    ].filter(Boolean).flat();
    result.push({ fromPort, toPort, sources: sources.map(String), path: `ingress[${index}]` });
  }
  return result;
}

function hasWildcardIam(value) {
  const scan = item => {
    if (item == null) return false;
    if (typeof item === 'string') {
      const s = item.replace(/\\"/g, '"');
      return /(?:"Action"\s*:\s*"\*"|Action\s*[=:]\s*["']?\*|"Resource"\s*:\s*"\*"|Resource\s*[=:]\s*["']?\*)/i.test(s);
    }
    if (Array.isArray(item)) return item.some(scan);
    if (typeof item === 'object') {
      for (const [key, child] of Object.entries(item)) {
        if (/^(Action|Resource)$/i.test(key)) {
          if (child === '*' || (Array.isArray(child) && child.includes('*'))) return true;
        }
        if (scan(child)) return true;
      }
    }
    return false;
  };
  return scan(value);
}

function inferConservativeLinks(resources, existingLinks) {
  // Inference is deliberately conservative and never mixed with confirmed links.
  const links = [];
  const confirmed = new Set(existingLinks.map(l => `${l.source}=>${l.target}`));
  const byCategory = category => resources.filter(r => r.category === category);
  for (const compute of byCategory('compute')) {
    for (const obs of byCategory('observability')) {
      const key = `${compute.id}=>${obs.id}`;
      if (!confirmed.has(key)) links.push({ source: compute.id, target: obs.id, label: 'possible telemetry relationship', confidence: 'inferred', evidence: { reason: 'category heuristic' } });
    }
  }
  return dedupeLinks(links).slice(0, 20);
}

function finding(severity, title, resource, description, recommendation, confidence, evidence) {
  const ruleId = `IV-${String(resource.provider || 'GEN').toUpperCase().replace(/[^A-Z0-9]+/g, '-')}-${title.toUpperCase().replace(/[^A-Z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48)}`;
  return { id: makeId(`${resource.id}-${title}`), ruleId, severity, title, resource: resource.id, description, recommendation, confidence, evidence };
}

function calculatePostureScore(findings) {
  const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0) * (CONFIDENCE_WEIGHT[f.confidence] || 0.5), 0);
  return Math.max(0, Math.round(100 - Math.min(100, penalty)));
}

function calculatePrRisk(findings, diffs) {
  const findingPenalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0) * (CONFIDENCE_WEIGHT[f.confidence] || 0.5), 0);
  const changePenalty = diffs.reduce((sum, diff) => {
    const base = diff.action === 'delete' ? 8 : diff.action === 'replace' ? 7 : diff.action === 'change' ? 4 : 2;
    const sensitive = /iam|security|firewall|route|gateway|db|database|kms|key|policy/i.test(diff.type || diff.resource || '') ? 5 : 0;
    return sum + base + sensitive;
  }, 0);
  return Math.min(100, Math.round(findingPenalty + changePenalty));
}

function approvalDecision(score, findings, diffs) {
  if (findings.some(f => f.severity === 'critical' && f.confidence === 'confirmed')) return 'Block until remediated';
  if (diffs.some(d => d.action === 'delete' && /db|database|kms|key|iam|security/i.test(d.type || d.resource || ''))) return 'Senior review required';
  if (score >= 70) return 'Block until remediated';
  if (score >= 40) return 'Senior review required';
  if (score >= 18) return 'Approve with comments';
  return 'Low-risk approval';
}

function buildResourceDiffs(beforeResources, afterResources) {
  const before = new Map((beforeResources || []).map(r => [resourceIdentity(r), normalizeResource(r)]));
  const after = new Map((afterResources || []).map(r => [resourceIdentity(r), normalizeResource(r)]));
  const diffs = [];
  for (const [key, resource] of after) {
    if (!before.has(key)) diffs.push({ action: 'add', resource: key, type: resource.type, description: 'Resource is present in proposed input but not the baseline.' });
    else if (stableStringify(before.get(key).attributes) !== stableStringify(resource.attributes)) diffs.push({ action: 'change', resource: key, type: resource.type, description: 'Declared resource attributes differ from the baseline.' });
  }
  for (const [key, resource] of before) if (!after.has(key)) diffs.push({ action: 'delete', resource: key, type: resource.type, description: 'Resource is absent from proposed input.' });
  return diffs;
}

function normalizeResource(resource) {
  const type = String(resource.type || typeFromAddress(resource.address || resource.id || 'unknown'));
  const name = String(resource.name || nameFromAddress(resource.address || resource.id || type));
  const id = String(resource.id || resource.address || `${type}.${name}`);
  const reserved = new Set(['id', 'address', 'moduleAddress', 'mode', 'type', 'name', 'provider', 'category', 'action', 'attributes', 'values', 'source', 'raw']);
  const directAttributes = Object.fromEntries(Object.entries(resource || {}).filter(([key]) => !reserved.has(key)));
  const attrs = resource.attributes ?? resource.values ?? directAttributes;
  return {
    id, address: resource.address || id, moduleAddress: resource.moduleAddress || null, mode: resource.mode || 'managed',
    type, name, provider: resource.provider || providerFromType(type), category: resource.category || classifyType(type),
    action: resource.action || 'present', attributes: attrs, source: resource.source || { kind: 'normalized' }
  };
}

function providerFromType(type = '') {
  const t = String(type).toLowerCase();
  if (t.startsWith('aws_') || t.startsWith('aws::')) return 'AWS';
  if (t.startsWith('azurerm_') || t.startsWith('microsoft.')) return 'Azure';
  if (t.startsWith('google_') || t.startsWith('gcp_')) return 'GCP';
  if (t.startsWith('kubernetes_') || t.startsWith('k8s.')) return 'Kubernetes';
  return 'Other';
}

function classifyType(type = '') {
  const t = String(type).toLowerCase();
  if (/vpc|subnet|route|gateway|loadbalancer|load_balancer|\blb\b|listener|eip|firewall|network|vpn|dns|route53|ingress|service$/.test(t)) return 'network';
  if (/iam|policy|role|security_group|securitygroup|kms|secret|certificate|waf|acl|guardduty|service_account|serviceaccount|network_security_group/.test(t)) return 'security';
  if (/instance|launch|autoscaling|ecs|eks|lambda|function|container|node|compute|app_service|deployment|stateful_set|daemon_set|pod|job|cron_job/.test(t)) return 'compute';
  if (/db_|database|rds|dynamodb|elasticache|redis|postgres|mysql|aurora|sql|cloudsql/.test(t)) return 'data';
  if (/s3|bucket|ebs|efs|volume|storage|backup|snapshot|blob|persistent_volume|persistentvolume/.test(t)) return 'storage';
  if (/cloudwatch|cloudtrail|log|monitor|alarm|metric|observability|sns|event|prometheus|grafana/.test(t)) return 'observability';
  return 'other';
}

function groupResources(resources, findings) {
  return Object.entries(CATEGORY_META).map(([category, meta]) => {
    const groupedResources = resources.filter(r => r.category === category);
    const ids = new Set(groupedResources.map(r => r.id));
    return { ...meta, category, resources: groupedResources, findings: findings.filter(f => ids.has(f.resource)) };
  }).sort((a, b) => a.order - b.order);
}

function countFindings(findings) {
  return findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, { critical: 0, high: 0, medium: 0, low: 0 });
}

function sortFindings(findings) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return findings.sort((a, b) => order[a.severity] - order[b.severity] || a.title.localeCompare(b.title));
}

function dedupeById(resources) {
  const map = new Map();
  for (const r of resources) map.set(r.id, r);
  return Array.from(map.values());
}

function dedupeLinks(links) {
  const map = new Map();
  for (const link of links) {
    if (!link?.source || !link?.target || link.source === link.target) continue;
    const key = `${link.source}=>${link.target}:${link.label || ''}`;
    if (!map.has(key)) map.set(key, link);
  }
  return Array.from(map.values());
}

function hasResource(resources, id) { return resources.some(r => r.id === id); }
function resourceIdentity(r) { return String(r.id || r.address || `${r.type}.${r.name}`); }
function typeFromAddress(address = '') { return String(address).split('.').find(part => /^(aws_|azurerm_|google_|kubernetes_)/.test(part)) || String(address).split('.')[0] || 'unknown'; }
function nameFromAddress(address = '') { const parts = String(address).split('.'); const i = parts.findIndex(part => /^(aws_|azurerm_|google_|kubernetes_)/.test(part)); return (parts[i + 1] || parts[1] || 'unnamed').replace(/\[.*$/, ''); }
function normalizeTerraformActions(actions) { const s = (actions || []).join(','); if (s === 'create') return 'add'; if (s === 'delete') return 'delete'; if (s.includes('delete') && s.includes('create')) return 'replace'; if (s === 'update') return 'change'; return 'present'; }
function firstDefined(...values) { return values.find(v => v !== undefined && v !== null); }
function isWorldCidr(value) { return ['0.0.0.0/0', '::/0', '*'].includes(String(value).trim()); }
function expandPortRange(from, to) { if (!Number.isFinite(from) || !Number.isFinite(to)) return []; if (to - from > 1000) return Array.from(SENSITIVE_PORTS).filter(p => p >= from && p <= to); return Array.from({ length: Math.max(0, to - from + 1) }, (_, i) => from + i); }
function parsePortToken(token) { const s = String(token || ''); if (/^\d+$/.test(s)) return [Number(s)]; const m = /^(\d+)-(\d+)$/.exec(s); return m ? expandPortRange(Number(m[1]), Number(m[2])) : []; }
function snakeCase(value) { return String(value).replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[-\s]+/g, '_').toLowerCase(); }
function makeId(seed) { let h = 2166136261; for (const c of String(seed)) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return `f-${(h >>> 0).toString(16)}`; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',')}}`; return JSON.stringify(value); }

function redactSensitive(value, sensitiveSpec) {
  if (sensitiveSpec === true) return '[sensitive]';
  if (value == null || sensitiveSpec == null || sensitiveSpec === false) return value;
  if (Array.isArray(value)) return value.map((item, index) => redactSensitive(item, Array.isArray(sensitiveSpec) ? sensitiveSpec[index] : sensitiveSpec?.[index]));
  if (typeof value === 'object') {
    const out = {};
    for (const [key, child] of Object.entries(value)) out[key] = redactSensitive(child, typeof sensitiveSpec === 'object' ? sensitiveSpec[key] : false);
    return out;
  }
  return value;
}
