import yaml from 'js-yaml';
import { parse as parseHcl } from '@cdktf/hcl2json';

const SEVERITY_WEIGHT = { critical: 35, high: 18, medium: 8, low: 3 };
const CONFIDENCE_WEIGHT = { confirmed: 1, high: 0.85, medium: 0.6, low: 0.35, inferred: 0.2 };
const FINDING_KIND_WEIGHT = { exposure: 1, privilege: 1, data_protection: 0.9, hardening: 0.55, availability: 0.35, operational: 0.4 };
const ADMIN_PORTS = new Set([22, 3389]);
const DATA_PORTS = new Set([3306, 5432, 6379, 9200, 9300, 27017, 27018, 1433, 1521, 9042]);
const SENSITIVE_PORTS = new Set([...ADMIN_PORTS, ...DATA_PORTS]);
const PRIVILEGED_IAM_SERVICES = new Set(['iam', 'kms', 'organizations', 'sts', 'secretsmanager', 'ssm']);

const CATEGORY_META = {
  network: { label: 'Network Edge', order: 1 },
  security: { label: 'Identity & Security', order: 2 },
  compute: { label: 'Compute Runtime', order: 3 },
  data: { label: 'Data Layer', order: 4 },
  storage: { label: 'Storage & Backup', order: 5 },
  observability: { label: 'Observability', order: 6 },
  other: { label: 'Other Resources', order: 7 }
};

// Bound parsed structures as well as request bytes: YAML aliases and very deep
// documents otherwise make recursive inspection and JSON serialization unsafe.
const MAX_RESOURCES = 2000;
function validateStructure(value) {
  const ancestors = new Set();
  let visited = 0;
  const visit = (item, depth) => {
    if (++visited > 250000) throw new Error('The document is too complex. Split it into smaller workspaces.');
    if (depth > 80) throw new Error('The document exceeds the maximum nesting depth of 80.');
    if (!item || typeof item !== 'object') return;
    if (ancestors.has(item)) throw new Error('Circular YAML aliases are not supported.');
    ancestors.add(item);
    for (const child of Object.values(item)) visit(child, depth + 1);
    ancestors.delete(item);
  };
  visit(value, 0);
  return value;
}

function validateRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Send a JSON object containing text or files.');
  if (body.text != null && typeof body.text !== 'string') throw new Error('Source text must be a string.');
  if (body.filename != null && typeof body.filename !== 'string') throw new Error('The filename must be a string.');
  if (body.files != null && !Array.isArray(body.files)) throw new Error('Files must be an array of named text files.');
  if (body.files?.length > 100) throw new Error('A maximum of 100 files can be analyzed in one request.');
  for (const file of body.files || []) {
    if (!file || typeof file !== 'object' || typeof file.content !== 'string' || (file.name != null && typeof file.name !== 'string')) throw new Error('Each file must contain a name and text content.');
  }
  if (body.baseline != null) {
    validateStructure(body.baseline);
    if (!body.baseline || typeof body.baseline !== 'object' || !Array.isArray(body.baseline.resources)) throw new Error('The baseline must contain a resources array.');
    if (body.baseline.resources.length > MAX_RESOURCES) throw new Error(`A maximum of ${MAX_RESOURCES} baseline resources is supported.`);
    body.baseline.resources.forEach(normalizeResource);
  }
}

export async function analyzeRequest(body) {
  validateRequest(body);
  const files = normalizeFiles(body.files, body.text || '', body.filename);
  // File upload previews are presentation text; the actual files are authoritative.
  const text = files[0]?.content || '';
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
  const diffs = result.workspace.analysisMode === 'terraform-plan-json'
    ? planChanges : buildResourceDiffs(baselineResources, result.workspace.resources);
  const reviewBaseline = result.workspace.analysisMode === 'terraform-plan-json'
    ? (() => {
        const previous = new Map(result.analysis.resources.map(r => [r.id, r]));
        for (const diff of diffs) {
          if (diff.action === 'add') previous.delete(diff.resource);
          else if (diff.before && typeof diff.before === 'object') previous.set(diff.resource, normalizeResource({ id: diff.resource, type: diff.type, name: diff.name, attributes: diff.before }));
          else previous.delete(diff.resource);
        }
        return [...previous.values()];
      })()
    : baselineResources.map(normalizeResource);
  const counts = diffs.reduce((acc, diff) => {
    const key = diff.action === 'replace' ? 'change' : diff.action;
    if (key in acc) acc[key] += 1;
    return acc;
  }, { add: 0, change: 0, delete: 0 });

  const reviewDelta = buildReviewFindingDelta(result, diffs, baselineResources);
  const riskScore = calculatePrRisk(reviewDelta.introduced, diffs);
  const decision = approvalDecision(riskScore, reviewDelta.introduced, diffs);
  return {
    ...result,
    review: {
      diffs,
      baselineResources: reviewBaseline,
      counts,
      riskScore,
      decision,
      findings: reviewDelta.all,
      introducedFindings: reviewDelta.introduced,
      existingFindings: reviewDelta.existing,
      resolvedFindings: reviewDelta.resolved,
      scoreModel: 'Change risk is based on findings introduced by added/changed/replaced resources plus destructive or sensitive resource actions. Pre-existing unchanged findings do not increase PR risk.'
    }
  };
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
  const families = new Set(files.map(file => /\.tf(?:\.json)?$/i.test(file.name) ? 'terraform' : /\.ya?ml$/i.test(file.name) ? 'yaml' : /\.json$/i.test(file.name) ? 'json' : null).filter(Boolean));
  if (families.size > 1) throw new Error('Import one infrastructure format at a time; mixed file formats cannot be combined reliably.');
  const type = explicitType === 'auto' ? detectType(text, files) : explicitType;
  if (type === 'json') {
    if (files.length > 1) {
      const docs = files.map(file => {
        try { return validateStructure(JSON.parse(file.content)); }
        catch (error) { if (!(error instanceof SyntaxError)) throw error; throw new Error(`JSON parsing failed in ${file.name}. Check the JSON syntax.`); }
      });
      if (docs.every(isKubernetesObject)) return parseKubernetesDocuments(docs, 'json');
      throw new Error('Import one JSON plan, state, or snapshot at a time. Multiple JSON files are supported only for Kubernetes manifests.');
    }
    return parseJsonDocument(text || files[0]?.content || '');
  }
  if (type === 'yaml') return parseYamlDocuments(text || files[0]?.content || '', files);
  if (type === 'terraform') return parseTerraformSource(files);
  throw new Error(`Unsupported input type: ${type}`);
}

function detectType(text, files) {
  const primary = String(text || files[0]?.content || '').trim();
  const names = files.map(file => file.name.toLowerCase());
  if (names.length && names.every(name => name.endsWith('.tf') || name.endsWith('.tf.json'))) return 'terraform';
  if (names.length && names.every(name => name.endsWith('.json'))) return 'json';
  if (primary.startsWith('{') || primary.startsWith('[')) return 'json';
  if (names.some(name => /\.ya?ml$/.test(name))) return 'yaml';
  if (/^\s*(apiVersion|kind|Resources|AWSTemplateFormatVersion|workspace|resources)\s*:/m.test(primary)) return 'yaml';
  if (/\b(resource|module|data|terraform|provider|variable|locals|output)\s+(?:"|\{)/.test(primary)) return 'terraform';
  if (/Terraform will perform the following actions|Plan:\s*\d+\s+to add/i.test(primary)) {
    throw new Error('Human-readable Terraform plan output is not a stable machine interface. Generate machine-readable plan JSON with: terraform show -json tfplan > plan.json');
  }
  return 'terraform';
}

function emptyWorkspace() {
  return {
    workspace: 'Empty workspace', sourceType: 'empty', analysisMode: 'empty', authoritative: false, evidenceLevel: 'none', runtimeVerified: false,
    importedAt: new Date().toISOString(), resources: [], explicitLinks: [], inferredLinks: [], diagnostics: [], changes: []
  };
}

function parseJsonDocument(text) {
  let doc;
  try { doc = JSON.parse(text); } catch { throw new Error('JSON parsing failed. Check for missing commas, quotes, or brackets.'); }
  validateStructure(doc);
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
      address: change.address,
      type: change.type,
      name: change.name || nameFromAddress(change.address),
      provider: providerFromType(change.type),
      providerName: change.provider_name || null,
      description: `Terraform plan actions: ${actions.join(', ') || 'no-op'}.`,
      before: redactSensitive(change?.change?.before, change?.change?.before_sensitive),
      after: redactSensitive(change?.change?.after, change?.change?.after_sensitive),
      sensitiveSpec: change?.change?.after_sensitive
    };
    if (action !== 'present' && change.mode !== 'data') changes.push(entry);
    changeMap.set(change.address, entry);
  }

  const hasUnknown = value => value === true || (value && typeof value === 'object' && Object.values(value).some(hasUnknown));
  const unknownCount = (doc.resource_changes || []).filter(r => hasUnknown(r.change?.after_unknown)).length;
  if (unknownCount) diagnostics.push({ level: 'warning', code: 'terraform-unknown-values', message: `${unknownCount} resource changes contain values that are not known until apply. Missing or unknown values are not passing controls; recheck with resolved state and runtime evidence.` });
  const isPlan = Boolean(doc.planned_values || doc.resource_changes);
  const root = isPlan ? doc.planned_values?.root_module : doc.values?.root_module;
  if (root) collectTerraformValueModule(root, resources, changeMap);
  else if (isPlan) {
    // A destroy plan may have no planned root. Prior state is never the proposed
    // architecture; use explicit after-values when supplied and omit deletions.
    for (const change of changeMap.values()) if (change.action !== 'delete' && change.after && typeof change.after === 'object') {
      resources.push(normalizeResource({ id: change.address, type: change.type, name: change.name, provider: change.provider, attributes: change.after, action: change.action, source: { kind: 'terraform-show-json', address: change.address } }));
    }
  }

  enforceResourceLimit(resources);
  const explicitLinks = collectTerraformConfigurationLinks(doc.configuration, resources);
  const mode = doc.planned_values || doc.resource_changes ? 'terraform-plan-json' : 'terraform-state-json';
  const evidenceLevel = mode === 'terraform-plan-json' ? 'planned-values' : 'state-snapshot';
  diagnostics.push({
    level: 'info', code: 'terraform-json-machine-readable',
    message: mode === 'terraform-plan-json'
      ? 'Terraform machine-readable plan JSON detected. Planned values, resource instances, and resource change actions are high-confidence evidence for this plan.'
      : 'Terraform machine-readable state JSON detected. Values are evidence from the supplied state snapshot; Sable does not claim that state is drift-free or identical to live cloud state.'
  });
  if (doc.planned_values || doc.values || doc.prior_state) {
    diagnostics.push({
      level: 'warning', code: 'terraform-sensitive-json',
      message: 'Terraform JSON can contain sensitive values. Sable redacts fields marked sensitive by Terraform before returning analysis data.'
    });
  }
  return {
    workspace: doc.terraform_version ? `Terraform ${doc.terraform_version} workspace` : 'Terraform workspace',
    sourceType: 'terraform-json', analysisMode: mode, authoritative: false, machineReadable: true, evidenceLevel,
    runtimeVerified: false,
    importedAt: new Date().toISOString(), resources, explicitLinks, inferredLinks: [], diagnostics, changes,
    scope: mode === 'terraform-plan-json' ? 'terraform-plan' : 'terraform-state-snapshot'
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
    const values = redactSensitive(redactSensitive(resource.values || change?.after || {}, resource.sensitive_values), change?.sensitiveSpec);
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
    const resolvedTarget = resolveTerraformResourceAddress(target, ids);
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
        childBindings[argument] = resolveBoundRefs(refs, inputBindings).map(ref => {
          const resolved = resolveTerraformResourceAddress(ref, ids, modulePrefix ? `${modulePrefix}.aws_placeholder.binding` : '');
          return resolved ? `@absolute:${resolved}` : ref;
        });
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
  if (!clean || /^(var|local|path|terraform)\./.test(clean)) return null;
  const marker = /(?:^|\.)(?:data\.)?(?:aws_|azurerm_|google_|kubernetes_)/.exec(targetAddress);
  const modulePrefix = marker ? targetAddress.slice(0, marker.index).replace(/\.$/, '') : '';
  const qualified = clean.startsWith('@absolute:') ? clean.slice(10) : (modulePrefix ? `${modulePrefix}.${clean}` : clean);
  const match = candidate => {
    const exact = [...ids].filter(id => candidate === id || candidate.startsWith(`${id}.`));
    if (exact.length) return exact.sort((a, b) => b.length - a.length)[0];
    const instances = [...ids].filter(id => id.startsWith(`${candidate}[`));
    return instances.length === 1 ? instances[0] : null;
  };
  // A module-local name must never silently bind to a same-named root resource.
  return match(qualified);
}

async function parseTerraformSource(files) {
  if (!files.length) throw new Error('No Terraform source was provided.');
  const resources = [];
  const explicitLinks = [];
  const diagnostics = [];
  for (const file of files) {
    if (!file.content.trim()) continue;
    let doc;
    try { doc = file.name.toLowerCase().endsWith('.tf.json') ? JSON.parse(file.content) : await parseHcl(file.name || 'input.tf', file.content); }
    catch { throw new Error(`Terraform HCL parsing failed in ${file.name}. Check the file syntax or import terraform show -json output.`); }
    validateStructure(doc);
    collectHclResources(doc, file.name, resources);
  }
  enforceResourceLimit(resources);
  const duplicateIds = resources.map(resource => resource.id).filter((id, index, all) => all.indexOf(id) !== index);
  if (duplicateIds.length) throw new Error(`Duplicate Terraform resource declarations detected: ${Array.from(new Set(duplicateIds)).join(', ')}`);
  const deduped = dedupeById(resources);
  const ids = new Set(deduped.map(resource => resource.id));
  for (const resource of deduped) {
    const refs = extractTerraformRefs(resource.attributes, ids);
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
    message: 'Raw .tf source is parsed with an HCL2 parser, but expressions, variables, for_each/count instances, provider defaults, remote modules, and runtime unknowns are not fully evaluated. For evaluated planned/state values and resource instances, import terraform show -json output from a plan or state.'
  });
  if (containsModuleBlocks(files)) diagnostics.push({
    level: 'warning', code: 'terraform-modules-unresolved',
    message: 'Module calls were detected. Source-only analysis does not claim resources inside remote or unprovided module directories. Include their .tf files or analyze plan JSON.'
  });
  return {
    workspace: files.length > 1 ? 'Terraform source workspace' : (files[0]?.name || 'Terraform source'),
    sourceType: 'terraform-hcl', analysisMode: 'terraform-static-source', authoritative: false,
    evidenceLevel: 'declaration-only', runtimeVerified: false,
    importedAt: new Date().toISOString(), resources: deduped, explicitLinks: dedupeLinks(explicitLinks), inferredLinks: [], diagnostics, changes: [], scope: 'provided-source-files'
  };
}

function collectHclResources(doc, fileName, resources) {
  const collect = (root, mode, prefix = '') => {
    for (const [type, names] of Object.entries(root || {})) {
      for (const [name, blocks] of Object.entries(names || {})) {
        const entries = Array.isArray(blocks) ? blocks : [blocks];
        entries.forEach((attrs, index) => {
          const base = `${prefix}${type}.${name}`;
          const id = `${base}${entries.length > 1 ? `[${index}]` : ''}`;
          resources.push(normalizeResource({
            id, address: id, mode, type, name, provider: providerFromType(type), category: classifyType(type),
            attributes: attrs || {}, action: 'present', source: { kind: 'terraform-hcl', file: fileName, address: id }
          }));
        });
      }
    }
  };
  collect(doc?.resource, 'managed');
  collect(doc?.data, 'data', 'data.');
}

function containsModuleBlocks(files) {
  return files.some(file => /(^|\n)\s*module\s+"/m.test(file.content));
}

function extractTerraformRefs(value, ids = new Set()) {
  const refs = new Set();
  const knownIds = Array.from(ids || []).sort((a, b) => b.length - a.length);
  const visit = (item, key = '') => {
    if (item == null) return;
    if (typeof item === 'string') {
      // HCL2 emits expressions as ${...}. A literal resource-like name in a
      // description is not dependency evidence. JSON depends_on uses raw IDs.
      const expressions = key === 'depends_on' ? [item] : [...item.matchAll(/(?<!\$)\$\{([^}]+)\}/g)].map(match => match[1]);
      if (!expressions.length) return;
      const expressionText = expressions.join(' ');
      for (const id of knownIds) {
        const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`(^|[^A-Za-z0-9_-])(${escaped})(?=($|[.\\[]))`, 'g');
        if (regex.test(expressionText)) refs.add(id);
      }
      const generic = /(?:module\.[A-Za-z0-9_-]+\.)*(?:[A-Za-z][A-Za-z0-9_-]*_[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+(?:\[[^\]]+\])?/g;
      for (const match of expressionText.matchAll(generic)) refs.add(match[0]);
      return;
    }
    if (Array.isArray(item)) return item.forEach(child => visit(child, key));
    if (typeof item === 'object') Object.entries(item).forEach(([childKey, child]) => visit(child, childKey));
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
      yaml.loadAll(source.content, doc => { if (doc != null) docs.push(validateStructure(doc)); }, { schema: cloudFormationSchema() });
    }
  } catch (error) {
    const location = error.mark ? ` at line ${error.mark.line + 1}, column ${error.mark.column + 1}` : '';
    if (!error.mark) throw error;
    throw new Error(`YAML parsing failed${location}. Check indentation and YAML syntax.`);
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
  enforceResourceLimit(resources);
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
    analysisMode: 'declarative-template', authoritative: false, evidenceLevel: 'declaration-only', runtimeVerified: false, importedAt: new Date().toISOString(),
    resources, explicitLinks: dedupeLinks(links), inferredLinks: [], diagnostics: [{ level: 'info', code: 'cloudformation-template', message: 'CloudFormation template declarations and intrinsic references were parsed. Deployment-time transforms, account controls, stack parameters not present here, and live resource state are outside this analysis.' }], changes: [], scope: 'provided-template'
  };
}

function collectCloudFormationRefs(value, refs) {
  if (value == null || typeof value !== 'object') return;
  if (Array.isArray(value)) return value.forEach(item => collectCloudFormationRefs(item, refs));
  if (typeof value.Ref === 'string') refs.add(value.Ref);
  const getAtt = value['Fn::GetAtt'] || value.GetAtt;
  if (typeof getAtt === 'string') refs.add(getAtt.split('.')[0]);
  if (Array.isArray(getAtt) && typeof getAtt[0] === 'string') refs.add(getAtt[0]);
  for (const [key, child] of Object.entries(value)) {
    if (key === 'Fn::Sub' || key === 'Sub') {
      const template = Array.isArray(child) ? child[0] : child;
      const bindings = Array.isArray(child) ? child[1] || {} : {};
      if (typeof template === 'string') for (const match of template.matchAll(/\$\{([A-Za-z0-9]+)(?:\.[^}]+)?\}/g)) {
        if (!Object.hasOwn(bindings, match[1])) refs.add(match[1]);
      }
      collectCloudFormationRefs(bindings, refs);
    } else collectCloudFormationRefs(child, refs);
  }
}

function isKubernetesObject(doc) {
  return Boolean(doc && typeof doc === 'object' && typeof doc.apiVersion === 'string' && typeof doc.kind === 'string');
}

function parseKubernetesDocuments(docs, sourceType) {
  const expanded = [];
  const expand = doc => {
    if (typeof doc.kind === 'string' && doc.kind.endsWith('List') && Array.isArray(doc.items)) {
      const itemKind = doc.kind === 'List' ? null : doc.kind.slice(0, -4);
      for (const item of doc.items) {
        if (!item || typeof item !== 'object') throw new Error('Each Kubernetes list item must be an object.');
        const resolved = { ...item, apiVersion: item.apiVersion || doc.apiVersion, kind: item.kind || itemKind };
        if (!isKubernetesObject(resolved)) throw new Error('Each Kubernetes List item must include kind and apiVersion.');
        expand(resolved);
      }
    } else expanded.push(doc);
  };
  docs.forEach(expand);
  enforceResourceLimit(expanded);
  const resources = expanded.map(original => {
    const doc = redactKubernetesSecret(original);
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
    workspace: 'Kubernetes manifests', sourceType: `kubernetes-${sourceType}`, analysisMode: 'declarative-manifest', authoritative: false, evidenceLevel: 'declaration-only', runtimeVerified: false,
    importedAt: new Date().toISOString(), resources, explicitLinks: links, inferredLinks: [], diagnostics: [{ level: 'info', code: 'kubernetes-manifest', message: 'Kubernetes manifests were parsed structurally. Admission mutations, cluster defaults, controllers, runtime network policy, and live workload state are outside this analysis unless explicitly present in the manifests.' }], changes: [], scope: 'provided-manifests'
  };
}

function buildKubernetesLinks(resources) {
  const links = [];
  const byKindNameNs = new Map();
  for (const r of resources) {
    const doc = r.attributes || {};
    byKindNameNs.set(`${doc.kind}:${doc.metadata?.namespace || 'default'}:${doc.metadata?.name}`, r.id);
  }
  const add = (source, target, label, evidence) => {
    if (!source || !target || source === target) return;
    links.push({ source, target, label, confidence: 'confirmed', evidence });
  };
  const workloads = resources.filter(r => /deployment|stateful_set|daemon_set|pod|job|cron_job|replica_set/.test(r.type));
  const workloadLabels = workload => {
    const doc = workload.attributes || {};
    return doc.kind === 'Pod' ? (doc.metadata?.labels || {}) : (doc.spec?.jobTemplate?.spec?.template?.metadata?.labels || doc.spec?.template?.metadata?.labels || {});
  };
  const selectorMatches = (selector, labels) => selector && Object.keys(selector).length && Object.entries(selector).every(([k, v]) => labels[k] === v);

  for (const service of resources.filter(r => r.type === 'kubernetes_service')) {
    const doc = service.attributes;
    const selector = doc.spec?.selector || {};
    if (Object.keys(selector).length) {
      for (const workload of workloads) {
        const wdoc = workload.attributes;
        const ns = wdoc.metadata?.namespace || 'default';
        if (ns !== (doc.metadata?.namespace || 'default')) continue;
        if (selectorMatches(selector, workloadLabels(workload))) add(service.id, workload.id, 'Service selector', { selector });
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
    for (const name of names) add(ingress.id, byKindNameNs.get(`Service:${ns}:${name}`), 'Ingress backend', { service: name });
  }

  for (const workload of workloads) {
    const doc = workload.attributes;
    const ns = doc.metadata?.namespace || 'default';
    const spec = kubernetesPodSpec(doc) || {};
    if (spec.serviceAccountName) add(byKindNameNs.get(`ServiceAccount:${ns}:${spec.serviceAccountName}`), workload.id, 'Service account', { serviceAccountName: spec.serviceAccountName });

    for (const volume of spec.volumes || []) {
      const candidates = [
        ['Secret', volume.secret?.secretName],
        ['ConfigMap', volume.configMap?.name],
        ['PersistentVolumeClaim', volume.persistentVolumeClaim?.claimName]
      ];
      for (const [kind, name] of candidates) if (name) add(byKindNameNs.get(`${kind}:${ns}:${name}`), workload.id, 'Volume/config reference', { kind, name });
    }

    for (const container of [...(spec.containers || []), ...(spec.initContainers || []), ...(spec.ephemeralContainers || [])]) {
      for (const from of container.envFrom || []) {
        if (from.secretRef?.name) add(byKindNameNs.get(`Secret:${ns}:${from.secretRef.name}`), workload.id, 'Environment secret reference', { container: container.name, secret: from.secretRef.name });
        if (from.configMapRef?.name) add(byKindNameNs.get(`ConfigMap:${ns}:${from.configMapRef.name}`), workload.id, 'Environment ConfigMap reference', { container: container.name, configMap: from.configMapRef.name });
      }
      for (const env of container.env || []) {
        if (env.valueFrom?.secretKeyRef?.name) add(byKindNameNs.get(`Secret:${ns}:${env.valueFrom.secretKeyRef.name}`), workload.id, 'Environment secret reference', { container: container.name, variable: env.name, secret: env.valueFrom.secretKeyRef.name });
        if (env.valueFrom?.configMapKeyRef?.name) add(byKindNameNs.get(`ConfigMap:${ns}:${env.valueFrom.configMapKeyRef.name}`), workload.id, 'Environment ConfigMap reference', { container: container.name, variable: env.name, configMap: env.valueFrom.configMapKeyRef.name });
      }
    }
  }

  for (const hpa of resources.filter(r => r.type === 'kubernetes_horizontal_pod_autoscaler')) {
    const doc = hpa.attributes || {};
    const ns = doc.metadata?.namespace || 'default';
    const ref = doc.spec?.scaleTargetRef;
    if (ref?.kind && ref?.name) add(hpa.id, byKindNameNs.get(`${ref.kind}:${ns}:${ref.name}`), 'Scale target', { scaleTargetRef: ref });
  }

  for (const binding of resources.filter(r => /kubernetes_(cluster_)?role_binding$/.test(r.type))) {
    const doc = binding.attributes || {};
    const ns = doc.metadata?.namespace || 'default';
    const roleRef = doc.roleRef;
    if (roleRef?.kind && roleRef?.name) {
      const roleNs = roleRef.kind === 'ClusterRole' ? 'default' : ns;
      add(byKindNameNs.get(`${roleRef.kind}:${roleNs}:${roleRef.name}`), binding.id, 'RBAC role reference', { roleRef });
    }
    for (const subject of doc.subjects || []) {
      if (subject.kind === 'ServiceAccount' && subject.name) {
        add(byKindNameNs.get(`ServiceAccount:${subject.namespace || ns}:${subject.name}`), binding.id, 'RBAC subject', { subject });
      }
    }
  }

  for (const policy of resources.filter(r => r.type === 'kubernetes_network_policy')) {
    const doc = policy.attributes || {};
    const ns = doc.metadata?.namespace || 'default';
    const selector = doc.spec?.podSelector;
    if (!selector || typeof selector !== 'object') continue;
    for (const workload of workloads) {
      const wdoc = workload.attributes || {};
      if ((wdoc.metadata?.namespace || 'default') !== ns) continue;
      if (matchesLabelSelector(selector, workloadLabels(workload))) add(policy.id, workload.id, 'NetworkPolicy selector', { selector });
    }
  }

  return dedupeLinks(links);
}

function matchesLabelSelector(selector, labels) {
  if (!Object.entries(selector.matchLabels || {}).every(([key, value]) => labels[key] === value)) return false;
  return (selector.matchExpressions || []).every(expression => {
    const exists = Object.hasOwn(labels, expression.key);
    const values = expression.values || [];
    if (expression.operator === 'In') return exists && values.includes(labels[expression.key]);
    if (expression.operator === 'NotIn') return !exists || !values.includes(labels[expression.key]);
    if (expression.operator === 'Exists') return exists;
    if (expression.operator === 'DoesNotExist') return !exists;
    return false;
  });
}

function parseNormalizedSnapshot(doc, sourceType) {
  const root = Array.isArray(doc) ? { workspace: 'Imported snapshot', resources: doc } : doc;
  enforceResourceLimit(root.resources || []);
  const resources = (root.resources || []).map((resource, index) => {
    if (!resource || typeof resource !== 'object' || Array.isArray(resource)) throw new Error('Each resource must be an object.');
    return normalizeResource({ ...resource, id: resource.id || resource.address || `${resource.type || 'unknown'}.${resource.name || index}` });
  });
  const ids = new Set(resources.map(resource => resource.id));
  const aliases = new Map();
  for (const resource of resources) for (const alias of [`${resource.type}.${resource.name}`, resource.name]) {
    const matches = aliases.get(alias) || new Set();
    matches.add(resource.id);
    aliases.set(alias, matches);
  }
  const resolve = identity => {
    if (ids.has(identity)) return identity;
    const matches = aliases.get(identity);
    if (matches?.size > 1) throw new Error(`Ambiguous relationship endpoint "${identity}". Use the full resource ID.`);
    return matches?.size === 1 ? [...matches][0] : null;
  };
  const relationships = root.relationships || root.links || [];
  if (!Array.isArray(relationships)) throw new Error('Snapshot relationships must be an array.');
  const links = relationships.map(link => {
    if (!link || typeof link !== 'object' || typeof link.source !== 'string' || typeof link.target !== 'string') throw new Error('Each relationship must contain source and target resource IDs.');
    const source = resolve(link.source), target = resolve(link.target);
    if (!source || !target) throw new Error(`Relationship endpoint not found: ${!source ? link.source : link.target}. Include the resource or remove the relationship.`);
    return { source, target, label: String(link.label || 'declared relationship'), confidence: link.confidence || 'confirmed', evidence: link.evidence || { source: 'snapshot' } };
  });
  return {
    workspace: root.workspace || root.name || 'Imported snapshot', sourceType: `snapshot-${sourceType}`, analysisMode: 'normalized-snapshot', authoritative: false, evidenceLevel: 'user-supplied', runtimeVerified: false,
    importedAt: new Date().toISOString(), resources, explicitLinks: dedupeLinks(links), inferredLinks: [], diagnostics: [{ level: 'info', code: 'normalized-snapshot', message: 'Normalized snapshot fields are treated as user-supplied declarations. Sable does not independently verify them against a cloud control plane.' }], changes: [], scope: 'provided-snapshot'
  };
}

function enforceResourceLimit(resources) {
  if (resources.length > MAX_RESOURCES) throw new Error(`A maximum of ${MAX_RESOURCES} resources can be analyzed at once. Split the workspace into smaller groups.`);
}

function finalizeAnalysis(workspace, options = {}) {
  enforceResourceLimit(workspace.resources || []);
  const normalized = (workspace.resources || []).map(normalizeResource);
  const seen = new Set();
  for (const resource of normalized) {
    if (seen.has(resource.id)) throw new Error(`Duplicate resource identity: ${resource.id}. Import a single unambiguous definition per resource.`);
    seen.add(resource.id);
  }
  const resources = normalized;
  const findings = [];
  for (const resource of resources) findings.push(...evaluateResource(resource, resources, workspace));
  const dedupedFindings = dedupeFindings(findings);
  const explicitLinks = dedupeLinks((workspace.explicitLinks || []).filter(link => hasResource(resources, link.source) && hasResource(resources, link.target)));
  const inferredLinks = options.includeInferred ? inferConservativeLinks(resources, explicitLinks) : [];
  const graph = { links: explicitLinks, inferredLinks };
  const counts = countFindings(dedupedFindings);
  const coverage = buildRuleCoverage(resources);
  const score = calculatePostureScore(dedupedFindings, coverage);
  const rating = calculatePostureRating(dedupedFindings, coverage);
  const grouped = groupResources(resources, dedupedFindings);
  const diagnostics = [...(workspace.diagnostics || [])];
  if (coverage.unsupportedResources > 0) diagnostics.push({
    level: 'warning', code: 'partial-rule-coverage',
    message: `${coverage.unsupportedResources} of ${coverage.importedResources} imported resources do not currently have a built-in posture rule family. They remain available in the architecture map but are not treated as passing security controls.`
  });
  if (resources.length && !workspace.runtimeVerified) diagnostics.push({
    level: 'info', code: 'runtime-state-not-verified',
    message: 'Sable analyzes the imported artifact. It does not query the live cloud/Kubernetes control plane, so effective runtime reachability, organization/account policies, drift, admission mutations, and external dependencies may differ.'
  });
  if (options.includeInferred && inferredLinks.length === 0 && resources.length) diagnostics.push({
    level: 'info', code: 'no-safe-inferred-relationships',
    message: 'No inferred architecture edges were added. Sable does not create category-based or name-based relationships without resource-specific evidence.'
  });
  return {
    workspace: { ...workspace, resources, explicitLinks, inferredLinks },
    analysis: {
      resources, findings: sortFindings(dedupedFindings), grouped, counts, score, rating, graph, diagnostics,
      metadata: {
        engineVersion: '3.5.0',
        analysisMode: workspace.analysisMode,
        authoritative: Boolean(workspace.authoritative),
        machineReadable: Boolean(workspace.machineReadable),
        evidenceLevel: workspace.evidenceLevel || (workspace.authoritative ? 'imported-machine-readable' : 'declaration-only'),
        runtimeVerified: Boolean(workspace.runtimeVerified),
        scope: workspace.scope,
        providersDetected: Array.from(new Set(resources.map(resource => resource.provider))).sort(),
        coverage,
        accuracyContract: 'S4BLE reports only claims supported by the imported artifact. It distinguishes a declared configuration from effective runtime behavior and does not turn missing properties into failures when provider defaults, account policies, module evaluation, admission controls, or live state could change the conclusion.',
        relationshipPolicy: 'Confirmed edges require explicit imported references/selectors/relationships. S4BLE does not infer generic category-to-category dependencies.',
        scoreModel: 'S4BLE Evidence Score is a transparent triage index over explicit findings in controls the built-in rule pack can assess. It is not a compliance score, a penetration test, or proof that the deployed environment is secure. Repeated instances of the same rule have diminishing score impact to avoid penalizing larger environments solely for size.'
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

function evaluateAws(resource) {
  const out = [];
  const type = resource.type.toLowerCase();
  const a = resource.attributes || {};

  if (/security_group|securitygroup|security_group_rule|security_group_ingress_rule/i.test(type)) {
    for (const rule of normalizeSecurityRules(a, type)) {
      if (rule.direction !== 'ingress' || !rule.sources.some(isWorldCidr)) continue;
      if (rule.allPorts) {
        out.push(finding('S4BLE-AWS-SG-001', 'critical', 'Internet ingress allows all ports/protocols', resource,
          'The declared ingress rule accepts traffic from a world-routable CIDR and does not restrict the protocol/port range.',
          'Limit the rule to the exact required protocol, ports, and trusted source ranges.', 'confirmed', { attribute: rule.path, value: rule },
          { kind: 'exposure', reference: 'AWS VPC security group rules' }));
        continue;
      }
      const adminPorts = Array.from(ADMIN_PORTS).filter(port => ruleIncludesPort(rule, port));
      if (adminPorts.length) out.push(finding('S4BLE-AWS-SG-002', 'high', 'Administrative port exposed to the internet', resource,
        `The declared ingress rule permits ${adminPorts.join(', ')} from a world-routable CIDR. This is a property of the security rule; actual host reachability still depends on attachment, routes, and the target resource.`,
        'Restrict administrative access to a VPN, identity-aware access path, bastion with trusted sources, or tightly scoped CIDRs.', 'confirmed', { attribute: rule.path, value: rule },
        { kind: 'exposure', limitations: 'A security-group rule alone does not prove that a public route or listening service exists.' }));
      const dataPorts = Array.from(DATA_PORTS).filter(port => ruleIncludesPort(rule, port));
      if (dataPorts.length) out.push(finding('S4BLE-AWS-SG-003', 'high', 'Data-service port exposed to the internet', resource,
        `The declared ingress rule permits data-service port(s) ${dataPorts.join(', ')} from a world-routable CIDR.`,
        'Use private connectivity and restrict source ranges to the workloads that require access.', 'confirmed', { attribute: rule.path, value: rule },
        { kind: 'exposure', limitations: 'The rule is public, but actual resource reachability also depends on routing and resource attachment.' }));
    }
  }

  const isRdsInstance = /(^|_)db_instance$|rds.*dbinstance|aws::rds::dbinstance/i.test(type);
  const isRdsCluster = /rds_cluster|aws::rds::dbcluster/i.test(type);
  if (isRdsInstance || isRdsCluster) {
    if (isRdsInstance) {
      const publicValue = scalarValue(firstDefined(a.publicly_accessible, a.PubliclyAccessible));
      if (publicValue === true) out.push(finding('S4BLE-AWS-RDS-001', 'high', 'Publicly addressable RDS endpoint requested', resource,
        'Public accessibility is explicitly enabled. AWS can assign a publicly addressable endpoint, but this setting alone does not prove internet reachability because VPC routing and security-group rules still apply.',
        'Prefer private database connectivity unless public addressing is a documented requirement, and verify that network policy limits access.', 'confirmed', { attribute: 'publicly_accessible/PubliclyAccessible', value: true },
        { kind: 'exposure', reference: 'Amazon RDS public accessibility' }));
      const multiAz = scalarValue(firstDefined(a.multi_az, a.MultiAZ));
      if (multiAz === false) out.push(finding('S4BLE-AWS-RDS-004', 'low', 'RDS Multi-AZ is explicitly disabled', resource,
        'The database is configured without Multi-AZ high availability. Whether this is a problem depends on the workload availability objective.',
        'For production workloads that require instance-level high availability, evaluate Multi-AZ or an engine-specific resilient topology.', 'confirmed', { attribute: 'multi_az/MultiAZ', value: false },
        { kind: 'availability', scoreEligible: false, limitations: 'Single-AZ can be appropriate for development, disposable, or cost-sensitive workloads.' }));
    }
    const encrypted = scalarValue(firstDefined(a.storage_encrypted, a.StorageEncrypted));
    if (encrypted === false) out.push(finding('S4BLE-AWS-RDS-002', 'high', 'RDS storage encryption explicitly disabled', resource,
      'The imported configuration explicitly sets RDS storage encryption to false.',
      'Enable RDS encryption at rest for workloads that store persistent data and verify the KMS key policy and recovery process.', 'confirmed', { attribute: 'storage_encrypted/StorageEncrypted', value: false },
      { kind: 'data_protection' }));
    const backup = scalarValue(firstDefined(a.backup_retention_period, a.BackupRetentionPeriod));
    if (isRdsInstance && (backup === 0 || backup === '0')) out.push(finding('S4BLE-AWS-RDS-003', 'medium', 'RDS automated backups disabled', resource,
      'The backup retention period is explicitly set to 0, which disables RDS automated backups for DB instances.',
      'Set a retention period that meets recovery objectives and test restoration. If another backup mechanism is intentionally used, document and verify it.', 'confirmed', { attribute: 'backup_retention_period/BackupRetentionPeriod', value: backup },
      { kind: 'data_protection', reference: 'Amazon RDS backup retention' }));
    const deletionProtection = scalarValue(firstDefined(a.deletion_protection, a.DeletionProtection));
    if (deletionProtection === false) out.push(finding('S4BLE-AWS-RDS-005', 'low', 'RDS deletion protection explicitly disabled', resource,
      'Deletion protection is explicitly disabled. This does not make deletion imminent, but it removes a provider-side guardrail.',
      'Enable deletion protection for persistent production databases unless a documented lifecycle process provides equivalent protection.', 'confirmed', { attribute: 'deletion_protection/DeletionProtection', value: false },
      { kind: 'data_protection', scoreEligible: false }));
    if (a.skip_final_snapshot === true) out.push(finding('S4BLE-AWS-RDS-006', 'medium', 'Terraform will skip the final RDS snapshot on deletion', resource,
      'skip_final_snapshot is explicitly true. If Terraform destroys this DB instance, it will not create the final snapshot requested by that Terraform resource setting.',
      'For persistent data, require a final snapshot or verify an independent backup/recovery process before destructive changes.', 'confirmed', { attribute: 'skip_final_snapshot', value: true },
      { kind: 'data_protection', scoreWeight: 0.7 }));
  }

  if (/s3_bucket($|_acl)|aws::s3::bucket$/i.test(type)) {
    const acl = String(scalarValue(firstDefined(a.acl, a.AccessControl, '')) || '').toLowerCase();
    if (/public-read|publicread|public-read-write|publicreadwrite/.test(acl)) out.push(finding('S4BLE-AWS-S3-001', 'high', 'Public S3 ACL declared', resource,
      'The imported configuration declares a public bucket ACL. Effective public access can still be blocked by stricter bucket, account, or organization Block Public Access settings.',
      'Prefer private ACLs and use narrowly scoped bucket policies or CloudFront origin access control when public delivery is required.', 'confirmed', { attribute: 'acl/AccessControl', value: acl },
      { kind: 'exposure', limitations: 'A public ACL declaration is not proof of effective public access when S3 Block Public Access is enforced at another level.' }));
  }

  const nestedPab = a.public_access_block_configuration || a.PublicAccessBlockConfiguration;
  if (/s3_bucket_public_access_block/i.test(type) || nestedPab) {
    const config = nestedPab || a;
    const controls = [
      ['BlockPublicAcls', firstDefined(config.block_public_acls, config.BlockPublicAcls)],
      ['IgnorePublicAcls', firstDefined(config.ignore_public_acls, config.IgnorePublicAcls)],
      ['BlockPublicPolicy', firstDefined(config.block_public_policy, config.BlockPublicPolicy)],
      ['RestrictPublicBuckets', firstDefined(config.restrict_public_buckets, config.RestrictPublicBuckets)]
    ];
    const disabled = controls.filter(([, value]) => scalarValue(value) === false).map(([name]) => name);
    if (disabled.length) out.push(finding('S4BLE-AWS-S3-002', 'medium', 'S3 bucket-level public-access guardrails are disabled', resource,
      `The imported bucket-level configuration explicitly disables: ${disabled.join(', ')}. This weakens bucket-level prevention, but account or organization settings may still enforce stricter protection.`,
      'Enable all four bucket-level Block Public Access settings unless public access is an explicit and reviewed requirement.', 'high', { attribute: 'PublicAccessBlockConfiguration', value: disabled },
      { kind: 'hardening', scoreWeight: 0.55, limitations: 'S3 applies the most restrictive effective combination of organization, account, access-point, and bucket settings.' }));
  }

  if (/s3_bucket_policy|aws::s3::bucketpolicy/i.test(type)) {
    const policy = firstDefined(a.policy, a.PolicyDocument);
    for (const exposure of analyzePublicBucketPolicy(policy)) {
      out.push(finding(exposure.ruleId, exposure.severity, exposure.title, resource, exposure.description, exposure.recommendation, exposure.confidence, exposure.evidence, exposure.options));
    }
  }

  if (/iam|aws::iam::/i.test(type)) {
    for (const issue of analyzeIamResource(resource)) {
      out.push(finding(issue.ruleId, issue.severity, issue.title, resource, issue.description, issue.recommendation, issue.confidence, issue.evidence, issue.options));
    }
  }

  if (/ebs_volume|aws::ec2::volume/i.test(type)) {
    const encrypted = scalarValue(firstDefined(a.encrypted, a.Encrypted));
    if (encrypted === false) out.push(finding('S4BLE-AWS-EBS-001', 'medium', 'EBS volume requests encryption disabled', resource,
      'The imported resource explicitly requests an unencrypted EBS volume.',
      'Enable EBS encryption and verify the effective account-level encryption-by-default setting and KMS key policy.', 'high', { attribute: 'encrypted/Encrypted', value: false },
      { kind: 'data_protection', limitations: 'Account-level EBS encryption-by-default can affect the effective result; Sable does not query the account control plane.' }));
  }

  if (/launch_template|instance$|aws::ec2::instance/i.test(type)) {
    const publicIp = scalarValue(firstDefined(a.associate_public_ip_address, a.AssociatePublicIpAddress));
    const networkInterfaces = firstDefined(a.network_interfaces, a.NetworkInterfaces) || [];
    const nestedPublic = (Array.isArray(networkInterfaces) ? networkInterfaces : [networkInterfaces]).some(n => scalarValue(firstDefined(n?.associate_public_ip_address, n?.AssociatePublicIpAddress)) === true);
    if (publicIp === true || nestedPublic) out.push(finding('S4BLE-AWS-EC2-001', 'medium', 'Public IP assignment explicitly enabled', resource,
      'The compute configuration explicitly requests a public IP on an interface. A public IP does not by itself prove that inbound traffic is allowed.',
      'Use private addressing for workloads that do not need direct internet addressing and verify routing and security-group exposure separately.', 'confirmed', { attribute: 'associate_public_ip_address/AssociatePublicIpAddress', value: true },
      { kind: 'exposure', scoreWeight: 0.55, limitations: 'Reachability still depends on subnet routing, security groups, network ACLs, and the service listening on the instance.' }));
  }

  if (/autoscaling_group|aws::autoscaling::autoscalinggroup/i.test(type)) {
    const max = scalarValue(firstDefined(a.max_size, a.MaxSize));
    if (max != null && Number.isFinite(Number(max)) && Number(max) <= 1) out.push(finding('S4BLE-AWS-ASG-001', 'low', 'Auto Scaling maximum capacity is one', resource,
      'The group cannot scale above one instance according to the imported maximum-capacity setting.',
      'Validate that a single-instance ceiling meets the workload availability and scaling objectives.', 'confirmed', { attribute: 'max_size/MaxSize', value: max },
      { kind: 'availability', scoreEligible: false }));
  }

  if (/lambda_function_url|aws::lambda::url/i.test(type)) {
    const authType = String(scalarValue(firstDefined(a.authorization_type, a.AuthType, '')) || '').toUpperCase();
    if (authType === 'NONE') out.push(finding('S4BLE-AWS-LAMBDA-URL-001', 'high', 'Lambda Function URL has no IAM authentication', resource,
      'The Function URL is explicitly configured with AuthType/authorization_type NONE, so the URL itself does not require AWS IAM authentication.',
      'Use AWS_IAM authentication unless anonymous invocation is an explicit requirement, and review the function resource policy before deployment.', 'confirmed', { attribute: 'authorization_type/AuthType', value: authType },
      { kind: 'exposure', limitations: 'Effective invocation also depends on the Lambda resource policy.' }));
  }

  return out;
}

function evaluateAzure(resource) {
  const out = [];
  const type = resource.type.toLowerCase();
  const a = resource.attributes || {};
  if (/network_security_group|network_security_rule|networksecuritygroups/.test(type)) {
    const rules = /network_security_rule$/.test(type) ? [a] : (a.security_rule || a.security_rules || a.securityRules || []);
    for (const [index, rule] of (Array.isArray(rules) ? rules : [rules]).entries()) {
      if (!rule || typeof rule !== 'object') continue;
      const direction = String(rule.direction || '').toLowerCase();
      if (!['tcp', 'udp', '*'].includes(String(rule.protocol || '').toLowerCase())) continue;
      const access = String(rule.access || '').toLowerCase();
      const sources = [rule.source_address_prefix, ...(rule.source_address_prefixes || [])].filter(Boolean).map(String);
      const publicSource = sources.some(isAzureInternetSource);
      const ports = parseAzurePortRanges(firstDefined(rule.destination_port_ranges, rule.destination_port_range));
      const allPorts = ports.all;
      if (direction === 'inbound' && access === 'allow' && publicSource && allPorts) out.push(finding('S4BLE-AZURE-NSG-001', 'critical', 'NSG declares a public allow rule for all ports', resource,
        'The declared inbound allow rule uses an internet-wide source and unrestricted ports. Higher-priority deny rules, security admin rules, and resource attachment can change effective access.', 'Restrict the source and destination ports to the minimum required.', 'confirmed', { attribute: `security_rule[${index}]`, value: rule }, { kind: 'exposure' }));
      else if (direction === 'inbound' && access === 'allow' && publicSource && Array.from(SENSITIVE_PORTS).some(port => ports.values.has(port))) out.push(finding('S4BLE-AZURE-NSG-002', 'high', 'NSG declares a public allow rule for a sensitive port', resource,
        'The declared rule permits a sensitive port from an internet-wide source. Effective access also depends on higher-priority rules and attachment; this is not a reachability test.', 'Restrict the source prefix and use managed administrative access paths.', 'confirmed', { attribute: `security_rule[${index}]`, value: rule }, { kind: 'exposure' }));
    }
  }
  if (/storage_account/.test(type)) {
    const publicAccess = scalarValue(firstDefined(a.allow_nested_items_to_be_public, a.allow_blob_public_access));
    if (publicAccess === true) out.push(finding('S4BLE-AZURE-STORAGE-001', 'low', 'Blob public-access capability enabled', resource,
      'The storage-account setting allows containers/blobs to be configured for anonymous public access. It does not prove that any container is currently public.',
      'Disable the capability unless anonymous blob access is an explicit requirement.', 'confirmed', { attribute: 'allow_nested_items_to_be_public/allow_blob_public_access', value: true },
      { kind: 'hardening', scoreEligible: false, limitations: 'Container-level configuration determines whether content is actually public.' }));
  }
  return out;
}

function evaluateGcp(resource) {
  const out = [];
  const type = resource.type.toLowerCase();
  const a = resource.attributes || {};
  if (/compute_firewall/.test(type)) {
    const sources = Array.isArray(a.source_ranges) ? a.source_ranges.map(String) : [];
    const world = sources.some(isWorldCidr)
      && (a.disabled === undefined || a.disabled === false)
      && (a.direction === undefined || String(a.direction).toUpperCase() === 'INGRESS');
    const allowed = Array.isArray(a.allow) ? a.allow : (a.allow ? [a.allow] : []);
    if (world) {
      let allPorts = false;
      const exposed = new Set();
      for (const rule of allowed) {
        const protocol = String(rule?.protocol || '').toLowerCase();
        const ports = rule?.ports || [];
        if (!['all', '-1', 'tcp', 'udp', '6', '17'].includes(protocol)) continue;
        if (protocol === 'all' || protocol === '-1' || ((['tcp', 'udp', '6', '17'].includes(protocol)) && (!ports || ports.length === 0))) allPorts = true;
        for (const port of (ports || []).flatMap(parsePortToken)) if (SENSITIVE_PORTS.has(port)) exposed.add(port);
      }
      if (allPorts) out.push(finding('S4BLE-GCP-FW-001', 'critical', 'GCP firewall allows internet ingress broadly', resource,
        'The firewall rule has a world-routable source range and an allow entry that does not restrict ports for the allowed protocol.', 'Restrict source ranges, protocols, and ports to the minimum required.', 'confirmed', { attribute: 'source_ranges/allow', value: { sources, allowed } }, { kind: 'exposure' }));
      else if (exposed.size) out.push(finding('S4BLE-GCP-FW-002', 'high', 'Sensitive GCP firewall port exposed publicly', resource,
        `The firewall rule allows sensitive port(s) ${Array.from(exposed).join(', ')} from a world-routable source range.`, 'Restrict source ranges or use identity-aware administrative access.', 'confirmed', { attribute: 'source_ranges/allow', value: { sources, allowed } }, { kind: 'exposure' }));
    }
  }
  if (/sql_database_instance/.test(type)) {
    const settings = Array.isArray(a.settings) ? a.settings[0] : a.settings;
    const ipConfigRaw = settings?.ip_configuration || a.ip_configuration;
    const ipConfig = Array.isArray(ipConfigRaw) ? ipConfigRaw[0] : ipConfigRaw;
    const ipv4 = scalarValue(ipConfig?.ipv4_enabled);
    if (ipv4 === true) out.push(finding('S4BLE-GCP-SQL-001', 'medium', 'Cloud SQL public IPv4 interface enabled', resource,
      'The database explicitly enables a public IPv4 interface. Authorized networks, IAM/database authentication, and other controls still determine who can connect.', 'Prefer private IP where practical and tightly scope authorized networks.', 'confirmed', { attribute: 'settings.ip_configuration.ipv4_enabled', value: true },
      { kind: 'exposure', scoreWeight: 0.55, limitations: 'A public interface is not equivalent to anonymous or unrestricted database access.' }));
    const authNetworks = ipConfig?.authorized_networks || [];
    const world = (Array.isArray(authNetworks) ? authNetworks : [authNetworks]).some(net => isWorldCidr(net?.value || net?.cidr_block || net));
    if (world) out.push(finding('S4BLE-GCP-SQL-002', 'high', 'Cloud SQL authorized network includes the entire internet', resource,
      'An authorized network explicitly includes 0.0.0.0/0 or ::/0.', 'Replace the world-routable CIDR with private connectivity or tightly scoped trusted source networks.', 'confirmed', { attribute: 'settings.ip_configuration.authorized_networks', value: authNetworks }, { kind: 'exposure' }));
  }
  return out;
}

function redactKubernetesSecret(doc) {
  if (doc?.kind !== 'Secret') return doc;
  const clean = structuredClone(doc);
  for (const field of ['data', 'stringData']) {
    if (clean[field] && typeof clean[field] === 'object')
      clean[field] = Object.fromEntries(Object.keys(clean[field]).map(key => [key, '[sensitive]']));
  }
  if (clean.metadata?.annotations?.['kubectl.kubernetes.io/last-applied-configuration'])
    clean.metadata.annotations['kubectl.kubernetes.io/last-applied-configuration'] = '[sensitive]';
  return clean;
}

function kubernetesPodSpec(doc) {
  return doc.spec?.jobTemplate?.spec?.template?.spec || doc.spec?.template?.spec || (doc.kind === 'Pod' ? doc.spec : null);
}

function evaluateKubernetes(resource) {
  const out = [];
  const doc = resource.attributes || {};
  const podSpec = kubernetesPodSpec(doc);
  if (!podSpec) return out;
  const linux = String(podSpec.os?.name || 'linux').toLowerCase() !== 'windows';
  if (podSpec.hostNetwork === true) out.push(finding('S4BLE-K8S-001', 'high', 'Pod uses the node network namespace', resource,
    'hostNetwork is explicitly enabled, reducing network isolation between the workload and node.', 'Disable hostNetwork unless the workload has a reviewed operational requirement.', 'confirmed', { attribute: 'spec.hostNetwork', value: true }, { kind: 'privilege', scoreWeight: 0.75 }));
  if (podSpec.hostPID === true) out.push(finding('S4BLE-K8S-002', 'high', 'Pod uses the node PID namespace', resource,
    'hostPID is explicitly enabled, exposing node process namespace visibility to the pod.', 'Disable hostPID unless a tightly controlled system workload requires it.', 'confirmed', { attribute: 'spec.hostPID', value: true }, { kind: 'privilege' }));
  if (podSpec.hostIPC === true) out.push(finding('S4BLE-K8S-003', 'high', 'Pod uses the node IPC namespace', resource,
    'hostIPC is explicitly enabled, reducing process-isolation boundaries.', 'Disable hostIPC unless a tightly controlled workload requires it.', 'confirmed', { attribute: 'spec.hostIPC', value: true }, { kind: 'privilege' }));
  for (const [index, volume] of (podSpec.volumes || []).entries()) {
    if (volume?.hostPath?.path) out.push(finding('S4BLE-K8S-004', 'medium', 'Pod mounts a hostPath volume', resource,
      `The pod mounts the node filesystem path ${volume.hostPath.path}. hostPath can expose node files to the workload depending on the path and mount mode.`, 'Prefer purpose-built volumes. If hostPath is required, minimize the path and use read-only mounts where possible.', 'confirmed', { attribute: `spec.volumes[${index}].hostPath`, value: volume.hostPath },
      { kind: 'privilege', scoreWeight: 0.65 }));
  }
  const podSecurity = podSpec.securityContext || {};
  const containers = [...(podSpec.containers || []), ...(podSpec.initContainers || []), ...(podSpec.ephemeralContainers || [])];
  for (const container of containers) {
    const sc = container.securityContext || {};
    const name = container.name || 'unnamed';
    if (sc.privileged === true) out.push(finding('S4BLE-K8S-005', 'critical', `Privileged container: ${name}`, resource,
      'The container explicitly requests privileged mode, which grants broad host-level capabilities.', 'Remove privileged mode and grant only the specific capabilities required.', 'confirmed', { attribute: `container.${name}.securityContext.privileged`, value: true }, { kind: 'privilege' }));
    if (linux && sc.allowPrivilegeEscalation === true) out.push(finding('S4BLE-K8S-006', 'high', `Privilege escalation explicitly allowed: ${name}`, resource,
      'allowPrivilegeEscalation is explicitly true for the container.', 'Set allowPrivilegeEscalation to false unless a reviewed workload requires it.', 'confirmed', { attribute: `container.${name}.securityContext.allowPrivilegeEscalation`, value: true }, { kind: 'privilege' }));
    const runAsNonRoot = firstDefined(sc.runAsNonRoot, podSecurity.runAsNonRoot);
    const runAsUser = firstDefined(sc.runAsUser, podSecurity.runAsUser);
    if (linux && (runAsNonRoot === false || runAsUser === 0)) out.push(finding('S4BLE-K8S-007', 'medium', `Container may run as root: ${name}`, resource,
      runAsNonRoot === false ? 'runAsNonRoot is explicitly false.' : 'runAsUser is explicitly set to UID 0.', 'Run the workload as a non-root UID unless root is required and separately mitigated.', 'confirmed', { attribute: `container.${name}.securityContext`, value: { runAsNonRoot, runAsUser } }, { kind: 'privilege', scoreWeight: 0.7 }));
    const addedCaps = (sc.capabilities?.add || []).map(cap => String(cap).toUpperCase());
    const dangerousCaps = addedCaps.filter(cap => ['ALL', 'SYS_ADMIN', 'SYS_MODULE', 'SYS_PTRACE', 'NET_ADMIN', 'DAC_READ_SEARCH'].includes(cap));
    if (dangerousCaps.length) out.push(finding('S4BLE-K8S-008', 'high', `Sensitive Linux capability added: ${name}`, resource,
      `The container explicitly adds ${dangerousCaps.join(', ')}.`, 'Remove unnecessary capabilities and start from a drop-all posture where practical.', 'confirmed', { attribute: `container.${name}.securityContext.capabilities.add`, value: dangerousCaps }, { kind: 'privilege' }));
    if (linux && String(sc.seccompProfile?.type || podSecurity.seccompProfile?.type || '').toLowerCase() === 'unconfined') out.push(finding('S4BLE-K8S-009', 'high', `Seccomp explicitly unconfined: ${name}`, resource,
      'The effective declared seccomp profile is Unconfined.', 'Use RuntimeDefault or a reviewed Localhost seccomp profile.', 'confirmed', { attribute: `container.${name}.securityContext.seccompProfile.type`, value: 'Unconfined' }, { kind: 'hardening' }));
  }
  return out;
}

function normalizeSecurityRules(a, resourceType = '') {
  const result = [];
  let ingress = firstDefined(a.ingress, a.SecurityGroupIngress, []);
  const standalone = ['from_port', 'FromPort', 'cidr_ipv4', 'cidr_ipv6', 'CidrIp', 'CidrIpv6', 'ip_protocol', 'IpProtocol'].some(key => a[key] !== undefined);
  const declaredType = String(firstDefined(a.type, '')).toLowerCase();
  const isIngressResource = /ingress/.test(resourceType) || declaredType === 'ingress' || (!/egress/.test(resourceType) && declaredType !== 'egress');
  if ((!Array.isArray(ingress) || !ingress.length) && standalone && isIngressResource) ingress = [a];
  for (const [index, rule] of (Array.isArray(ingress) ? ingress : [ingress]).entries()) {
    if (!rule || typeof rule !== 'object') continue;
    const protocol = String(scalarValue(firstDefined(rule.protocol, rule.ip_protocol, rule.IpProtocol, '')) || '').toLowerCase();
    const rawFrom = scalarValue(firstDefined(rule.from_port, rule.FromPort));
    const rawTo = scalarValue(firstDefined(rule.to_port, rule.ToPort, rawFrom));
    const fromPort = rawFrom === undefined || rawFrom === null || rawFrom === '' ? null : Number(rawFrom);
    const toPort = rawTo === undefined || rawTo === null || rawTo === '' ? fromPort : Number(rawTo);
    const sources = [
      ...(Array.isArray(rule.cidr_blocks) ? rule.cidr_blocks : (rule.cidr_blocks ? [rule.cidr_blocks] : [])),
      ...(Array.isArray(rule.ipv6_cidr_blocks) ? rule.ipv6_cidr_blocks : (rule.ipv6_cidr_blocks ? [rule.ipv6_cidr_blocks] : [])),
      rule.cidr_ipv4, rule.cidr_ipv6, rule.CidrIp, rule.CidrIpv6, rule.cidr, rule.source
    ].filter(Boolean).flat().map(String);
    const allPorts = protocol === '-1' || protocol === 'all' || (['tcp', 'udp', '6', '17'].includes(protocol) && Number.isFinite(fromPort) && Number.isFinite(toPort) && fromPort === 0 && toPort === 65535);
    result.push({ direction: 'ingress', protocol, fromPort, toPort, allPorts, sources, path: `ingress[${index}]` });
  }
  return result;
}

function ruleIncludesPort(rule, port) {
  if (rule.allPorts) return true;
  if (!['tcp', 'udp', '6', '17'].includes(rule.protocol)) return false;
  if (!Number.isFinite(rule.fromPort) || !Number.isFinite(rule.toPort)) return false;
  return port >= rule.fromPort && port <= rule.toPort;
}

function analyzeIamResource(resource) {
  const issues = [];
  const a = resource.attributes || {};
  const docs = [];
  const textPolicies = [];
  const addDoc = (kind, value, path) => {
    const parsed = parsePolicyValue(value);
    if (parsed) docs.push({ kind, doc: parsed, path });
    else if (typeof value === 'string' && value.trim()) textPolicies.push({ kind, text: value, path });
  };
  addDoc('identity', firstDefined(a.policy, a.PolicyDocument), 'policy/PolicyDocument');
  addDoc('trust', firstDefined(a.assume_role_policy, a.AssumeRolePolicyDocument), 'assume_role_policy/AssumeRolePolicyDocument');
  for (const [index, entry] of (Array.isArray(a.Policies) ? a.Policies : []).entries()) addDoc('identity', entry?.PolicyDocument, `Policies[${index}].PolicyDocument`);
  for (const [index, entry] of (Array.isArray(a.inline_policy) ? a.inline_policy : []).entries()) addDoc('identity', entry?.policy, `inline_policy[${index}].policy`);

  for (const { kind, doc, path } of docs) {
    const statements = Array.isArray(doc.Statement) ? doc.Statement : (doc.Statement ? [doc.Statement] : []);
    for (const [index, statement] of statements.entries()) {
      if (!statement || String(statement.Effect || 'Allow').toLowerCase() !== 'allow') continue;
      const conditionPresent = statement.Condition && Object.keys(statement.Condition).length > 0;
      if (kind === 'trust') {
        if (principalIsWildcard(statement.Principal) && !conditionPresent) issues.push({
          ruleId: 'S4BLE-AWS-IAM-TRUST-001', severity: 'critical', title: 'IAM role trust policy allows any principal',
          description: 'An Allow statement in the role trust policy uses a wildcard principal without a restricting Condition.',
          recommendation: 'Replace the wildcard principal with intended accounts/services/roles or add a narrowly scoped, reviewed condition.', confidence: 'confirmed',
          evidence: { attribute: `${path}.Statement[${index}]`, value: summarizePolicyStatement(statement) }, options: { kind: 'privilege' }
        });
        continue;
      }
      const actions = asStringArray(statement.Action);
      const resources = asStringArray(statement.Resource);
      const actionAll = actions.includes('*');
      const resourceAll = resources.includes('*');
      if (actionAll) issues.push({
        ruleId: 'S4BLE-AWS-IAM-001', severity: resourceAll && !conditionPresent ? 'critical' : 'high', title: 'IAM Allow statement uses Action "*"',
        description: conditionPresent
          ? 'An IAM Allow statement grants all AWS actions and relies on a Condition/resource scope to constrain use.'
          : 'An IAM Allow statement grants all AWS actions. This is substantially broader than least privilege.',
        recommendation: 'Replace Action "*" with the exact API actions required and scope resources/conditions where supported.', confidence: 'confirmed',
        evidence: { attribute: `${path}.Statement[${index}]`, value: summarizePolicyStatement(statement) }, options: { kind: 'privilege' }
      });
      const serviceWildcards = actions.filter(action => /^[a-z0-9-]+:\*$/i.test(action));
      for (const action of serviceWildcards) {
        const service = action.split(':')[0].toLowerCase();
        issues.push({
          ruleId: 'S4BLE-AWS-IAM-002', severity: PRIVILEGED_IAM_SERVICES.has(service) || resourceAll ? 'high' : 'medium', title: `Broad IAM service permission: ${action}`,
          description: `The Allow statement grants every action in the ${service} service${resourceAll ? ' across all resources' : ''}.`,
          recommendation: 'Replace service-wide wildcards with the exact actions required and resource-scope the statement where the service supports it.', confidence: 'confirmed',
          evidence: { attribute: `${path}.Statement[${index}]`, value: summarizePolicyStatement(statement) }, options: { kind: 'privilege', scoreWeight: 0.8 }
        });
      }
      if (statement.NotAction && resourceAll && !conditionPresent) issues.push({
        ruleId: 'S4BLE-AWS-IAM-003', severity: 'high', title: 'IAM Allow statement uses NotAction with Resource "*"',
        description: 'An Allow statement uses NotAction while applying to all resources, which can grant a much broader set of actions than the exclusions suggest.',
        recommendation: 'Prefer an explicit Action allow-list and scope resources and conditions to the intended use case.', confidence: 'confirmed',
        evidence: { attribute: `${path}.Statement[${index}]`, value: summarizePolicyStatement(statement) }, options: { kind: 'privilege' }
      });
    }
  }
  for (const { kind, text: policyText, path } of textPolicies) {
    const normalized = policyText.replace(/\\"/g, '"');
    const allow = /(?:"?Effect"?\s*[:=]\s*["']?Allow["']?)/i.test(normalized);
    if (!allow) continue;
    if (kind === 'trust' && /(?:"?Principal"?\s*[:=][\s\S]{0,80}["']?\*["']?)/i.test(normalized)) {
      issues.push({
        ruleId: 'S4BLE-AWS-IAM-TRUST-001', severity: 'high', title: 'IAM trust policy text contains a wildcard principal',
        description: 'Static source text contains an Allow trust-policy declaration with a wildcard Principal. S4BLE could not fully evaluate the expression, so conditions and computed values may change the effective result.',
        recommendation: 'Resolve the policy through terraform show -json and verify the final Principal and Condition.', confidence: 'high',
        evidence: { attribute: path, value: '[static policy expression contains Principal "*"]' },
        options: { kind: 'privilege', scoreWeight: 0.7, limitations: 'Textual static-source match; use Terraform plan JSON for the resolved policy document.' }
      });
    }
    if (kind === 'identity' && /(?:"?Action"?\s*[:=][\s\[]*["']\*["'])/i.test(normalized)) {
      issues.push({
        ruleId: 'S4BLE-AWS-IAM-001', severity: 'high', title: 'IAM policy source contains Action "*"',
        description: 'Static source text contains an Allow statement with Action "*". S4BLE could not fully evaluate the policy expression, so resource and condition scope may still constrain the final policy.',
        recommendation: 'Resolve the policy with terraform show -json and replace Action "*" with the exact actions required.', confidence: 'high',
        evidence: { attribute: path, value: '[static policy expression contains Action "*"]' },
        options: { kind: 'privilege', scoreWeight: 0.7, limitations: 'Textual static-source match; use Terraform plan JSON for resolved policy semantics.' }
      });
    }
  }
  return dedupeIssues(issues);
}

function analyzePublicBucketPolicy(value) {
  const doc = parsePolicyValue(value);
  if (!doc) return [];
  const issues = [];
  const statements = Array.isArray(doc.Statement) ? doc.Statement : (doc.Statement ? [doc.Statement] : []);
  for (const [index, statement] of statements.entries()) {
    if (!statement || String(statement.Effect || '').toLowerCase() !== 'allow') continue;
    if (!principalIsWildcard(statement.Principal)) continue;
    if (statement.Condition && Object.keys(statement.Condition).length) continue;
    const actions = asStringArray(statement.Action).map(value => value.toLowerCase());
    const write = actions.some(action => action === '*' || /s3:(put|delete|abort|restore|create|replicate|write)/.test(action) || action === 's3:*');
    issues.push({
      ruleId: write ? 'S4BLE-AWS-S3-004' : 'S4BLE-AWS-S3-003',
      severity: write ? 'critical' : 'high',
      title: write ? 'S3 bucket policy declares anonymous write-capable access' : 'S3 bucket policy declares anonymous access',
      description: write
        ? 'An unconditional Allow statement uses a wildcard principal and includes write-capable or service-wide S3 actions.'
        : 'An unconditional Allow statement uses a wildcard principal. The policy declaration is public; S3 Block Public Access may still reject or restrict it.',
      recommendation: 'Replace the wildcard principal with intended identities, or use a reviewed delivery pattern such as CloudFront when public read is required.',
      confidence: 'confirmed', evidence: { attribute: `PolicyDocument.Statement[${index}]`, value: summarizePolicyStatement(statement) },
      options: { kind: 'exposure', limitations: 'Effective access can still be blocked by S3 Block Public Access at bucket, account, access-point, or organization level.' }
    });
  }
  return issues;
}

function parsePolicyValue(value) {
  if (!value) return null;
  if (typeof value === 'object') return value;
  if (typeof value !== 'string') return null;
  let candidate = value.trim();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const parsed = JSON.parse(candidate);
      if (typeof parsed === 'string') { candidate = parsed; continue; }
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch { break; }
  }
  return null;
}

function principalIsWildcard(principal) {
  if (principal === '*') return true;
  if (Array.isArray(principal)) return principal.includes('*');
  if (principal && typeof principal === 'object') return Object.values(principal).flat().map(String).includes('*');
  return false;
}

function summarizePolicyStatement(statement) {
  return {
    Effect: statement.Effect,
    Action: statement.Action,
    NotAction: statement.NotAction,
    Resource: statement.Resource,
    NotResource: statement.NotResource,
    Principal: statement.Principal,
    Condition: statement.Condition ? '[present]' : undefined
  };
}

function asStringArray(value) {
  if (value == null) return [];
  return (Array.isArray(value) ? value : [value]).flat().filter(v => v != null).map(String);
}

function dedupeIssues(issues) {
  const seen = new Set();
  return issues.filter(issue => {
    const key = `${issue.ruleId}:${JSON.stringify(issue.evidence)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function isAzureInternetSource(value) {
  const s = String(value || '').trim().toLowerCase();
  return s === '*' || s === '0.0.0.0/0' || s === '::/0' || s === 'internet';
}

function parseAzurePortRanges(value) {
  const values = new Set();
  let all = false;
  const items = Array.isArray(value) ? value : (value == null ? [] : String(value).split(','));
  for (const item of items) {
    const token = String(item).trim();
    if (!token) continue;
    if (token === '*') { all = true; continue; }
    for (const port of parsePortToken(token)) values.add(port);
  }
  return { values, all };
}

function scalarValue(value) {
  let current = value;
  while (Array.isArray(current) && current.length === 1) current = current[0];
  return current;
}

function buildRuleCoverage(resources) {
  const postureResources = resources.filter(resource => resource.mode !== 'data');
  let supportedResources = 0;
  let applicableControlFamilies = 0;
  const byProvider = {};
  for (const resource of resources) byProvider[resource.provider] = (byProvider[resource.provider] || 0) + 1;
  for (const resource of postureResources) {
    const families = ruleFamiliesForResource(resource);
    if (families.length) supportedResources += 1;
    applicableControlFamilies += families.length;
  }
  const importedResources = resources.length;
  const postureResourceCount = postureResources.length;
  return {
    importedResources,
    postureResourceCount,
    dataSourceCount: importedResources - postureResourceCount,
    supportedResources,
    unsupportedResources: Math.max(0, postureResourceCount - supportedResources),
    supportedPercent: postureResourceCount ? Math.round((supportedResources / postureResourceCount) * 100) : 0,
    applicableControlFamilies,
    providerResourceCounts: byProvider,
    note: 'Coverage measures managed/imported resources with an applicable built-in S4BLE rule family. Terraform data sources are mapped but excluded from posture scoring. Coverage is not a compliance percentage.'
  };
}

function ruleFamiliesForResource(resource) {
  const type = String(resource.type || '').toLowerCase();
  if (resource.provider === 'AWS') {
    const families = [];
    if (/security_group|securitygroup|security_group_rule|security_group_ingress_rule/.test(type)) families.push('network-ingress');
    if (/db_instance|rds_cluster|aws::rds::db/.test(type)) families.push('database-protection');
    if (/s3_bucket|aws::s3::bucket/.test(type)) families.push('s3-access');
    if (/iam|aws::iam::/.test(type)) families.push('iam-policy');
    if (/ebs_volume|aws::ec2::volume/.test(type)) families.push('block-storage-encryption');
    if (/launch_template|instance$|aws::ec2::instance/.test(type)) families.push('compute-addressing');
    if (/autoscaling_group|aws::autoscaling::autoscalinggroup/.test(type)) families.push('autoscaling-capacity');
    if (/lambda_function_url|aws::lambda::url/.test(type)) families.push('lambda-url-auth');
    return families;
  }
  if (resource.provider === 'Azure') {
    const families = [];
    if (/network_security_group|network_security_rule|networksecuritygroups/.test(type)) families.push('network-ingress');
    if (/storage_account/.test(type)) families.push('storage-public-access-capability');
    return families;
  }
  if (resource.provider === 'GCP') {
    const families = [];
    if (/compute_firewall/.test(type)) families.push('network-ingress');
    if (/sql_database_instance/.test(type)) families.push('database-networking');
    return families;
  }
  if (resource.provider === 'Kubernetes') {
    return /deployment|stateful_set|daemon_set|pod|job|cron_job|replica_set/.test(type) ? ['pod-security'] : [];
  }
  return [];
}

function inferConservativeLinks() {
  // Correctness takes precedence over visual completeness. No relationship is
  // inferred merely because resources share a category, provider, or similar name.
  return [];
}

function finding(ruleId, severity, title, resource, description, recommendation, confidence, evidence, options = {}) {
  return {
    id: makeId(`${ruleId}-${resource.id}-${title}-${stableStringify(evidence)}`),
    ruleId,
    severity,
    title,
    resource: resource.id,
    description,
    recommendation,
    confidence,
    evidence,
    kind: options.kind || 'operational',
    scoreEligible: options.scoreEligible !== false,
    scoreWeight: Number.isFinite(options.scoreWeight) ? options.scoreWeight : 1,
    limitations: options.limitations || null,
    reference: options.reference || null
  };
}

function dedupeFindings(findings) {
  const map = new Map();
  for (const item of findings) {
    const key = `${item.ruleId}|${item.resource}|${stableStringify(item.evidence)}`;
    if (!map.has(key)) map.set(key, item);
  }
  return Array.from(map.values());
}

function calculatePostureScore(findings, coverage) {
  if (!coverage?.supportedResources) return null;
  const grouped = new Map();
  for (const item of findings) {
    if (item.scoreEligible === false) continue;
    const severity = SEVERITY_WEIGHT[item.severity] || 0;
    const confidence = CONFIDENCE_WEIGHT[item.confidence] ?? 0.5;
    const kindWeight = FINDING_KIND_WEIGHT[item.kind] ?? 0.5;
    const impact = severity * confidence * kindWeight * (Number.isFinite(item.scoreWeight) ? item.scoreWeight : 1);
    const list = grouped.get(item.ruleId) || [];
    list.push(impact);
    grouped.set(item.ruleId, list);
  }
  let penalty = 0;
  for (const values of grouped.values()) {
    values.sort((a, b) => b - a);
    if (!values.length) continue;
    const first = values[0];
    const repeats = values.slice(1).reduce((sum, value) => sum + value * 0.3, 0);
    penalty += Math.min(first * 1.8, first + repeats);
  }
  return Math.max(0, Math.round(100 - Math.min(100, penalty)));
}

function calculatePostureRating(findings, coverage) {
  if (!coverage?.supportedResources) return 'Not rated — no built-in controls apply';
  const eligible = findings.filter(item => item.scoreEligible !== false && (item.confidence === 'confirmed' || item.confidence === 'high'));
  if (eligible.some(item => item.severity === 'critical')) return 'Critical findings detected';
  if (eligible.some(item => item.severity === 'high')) return 'High-priority findings detected';
  if (eligible.some(item => item.severity === 'medium')) return 'Review recommended';
  if (eligible.some(item => item.severity === 'low')) return 'Advisory findings only';
  return 'No confirmed issues detected by assessed controls';
}

function buildReviewFindingDelta(result, diffs, baselineResources) {
  const changedIds = new Set(diffs.map(diff => diff.resource));
  const currentFindings = (result.analysis.findings || []).filter(item => changedIds.has(item.resource));
  const beforeFindings = [];
  const baselineMap = new Map((baselineResources || []).map(resource => [resourceIdentity(resource), normalizeResource(resource)]));

  for (const diff of diffs) {
    if (diff.action === 'add') continue;
    let beforeResource = null;
    if (diff.before && typeof diff.before === 'object') {
      beforeResource = normalizeResource({ id: diff.resource, address: diff.resource, type: diff.type, name: diff.name || nameFromAddress(diff.resource), provider: diff.provider || providerFromType(diff.type), attributes: diff.before });
    } else if (baselineMap.has(diff.resource)) beforeResource = baselineMap.get(diff.resource);
    if (!beforeResource) continue;
    beforeFindings.push(...evaluateResource(beforeResource, [beforeResource], { analysisMode: 'review-baseline' }));
  }

  const key = item => `${item.ruleId}|${item.resource}|${stableStringify(item.evidence)}`;
  const beforeMap = new Map(beforeFindings.map(item => [key(item), item]));
  const afterMap = new Map(currentFindings.map(item => [key(item), item]));
  const introduced = [];
  const existing = [];
  const resolved = [];
  for (const item of currentFindings) {
    if (beforeMap.has(key(item))) existing.push({ ...item, reviewStatus: 'pre-existing-on-changed-resource' });
    else introduced.push({ ...item, reviewStatus: 'introduced-or-newly-detectable' });
  }
  for (const item of beforeFindings) if (!afterMap.has(key(item))) resolved.push({ ...item, reviewStatus: 'resolved' });
  return { introduced, existing, resolved, all: [...introduced, ...existing] };
}

function calculatePrRisk(findings, diffs) {
  let score = findings.reduce((sum, item) => {
    const base = SEVERITY_WEIGHT[item.severity] || 0;
    const confidence = CONFIDENCE_WEIGHT[item.confidence] ?? 0.5;
    const kindWeight = FINDING_KIND_WEIGHT[item.kind] ?? 0.5;
    return sum + base * confidence * kindWeight * (Number.isFinite(item.scoreWeight) ? item.scoreWeight : 1);
  }, 0);
  for (const diff of diffs) {
    const identity = `${diff.type || ''} ${diff.resource || ''}`;
    if (diff.action === 'add') score += 2;
    if (diff.action === 'change') score += 3;
    if (diff.action === 'replace') score += 8;
    if (diff.action === 'delete') score += 8;
    if ((diff.action === 'delete' || diff.action === 'replace') && /db|database|rds|sql|dynamodb|kms|key|secret|bucket|storage/i.test(identity)) score += 14;
    else if (/iam|security|firewall|route|gateway|policy/i.test(identity)) score += 6;
  }
  return Math.min(100, Math.round(score));
}

function approvalDecision(score, findings, diffs) {
  if (findings.some(f => f.severity === 'critical' && f.confidence === 'confirmed')) return 'Block: confirmed critical change';
  if (diffs.some(d => (d.action === 'delete' || d.action === 'replace') && /db|database|rds|sql|kms|key|secret/i.test(`${d.type || ''} ${d.resource || ''}`))) return 'High-risk destructive change — senior review';
  if (score >= 65) return 'High-risk change — senior review';
  if (score >= 35) return 'Manual review required';
  if (score >= 15) return 'Review recommended';
  return 'No material risk detected in imported change';
}

function buildResourceDiffs(beforeResources, afterResources) {
  const before = new Map((beforeResources || []).map(r => [resourceIdentity(r), normalizeResource(r)]));
  const after = new Map((afterResources || []).map(r => [resourceIdentity(r), normalizeResource(r)]));
  const diffs = [];
  for (const [key, resource] of after) {
    if (!before.has(key)) diffs.push({ action: 'add', resource: key, type: resource.type, name: resource.name, provider: resource.provider, before: null, after: resource.attributes, description: 'Resource is present in proposed input but not the baseline.' });
    else if (stableStringify(before.get(key).attributes) !== stableStringify(resource.attributes)) {
      const previous = before.get(key);
      diffs.push({ action: 'change', resource: key, type: resource.type, name: resource.name, provider: resource.provider, before: previous.attributes, after: resource.attributes, description: 'Declared resource attributes differ from the baseline.' });
    }
  }
  for (const [key, resource] of before) if (!after.has(key)) diffs.push({ action: 'delete', resource: key, type: resource.type, name: resource.name, provider: resource.provider, before: resource.attributes, after: null, description: 'Resource is absent from proposed input.' });
  return diffs;
}

function normalizeResource(resource) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) throw new Error('Each resource must be an object.');
  const type = String(resource.type || typeFromAddress(resource.address || resource.id || 'unknown'));
  const name = String(resource.name || nameFromAddress(resource.address || resource.id || type));
  const id = String(resource.id || resource.address || `${type}.${name}`);
  const reserved = new Set(['id', 'address', 'moduleAddress', 'mode', 'type', 'name', 'provider', 'category', 'action', 'attributes', 'values', 'source', 'raw']);
  const directAttributes = Object.fromEntries(Object.entries(resource || {}).filter(([key]) => !reserved.has(key)));
  const attrs = resource.attributes ?? resource.values ?? directAttributes;
  return {
    id, address: resource.address || id, moduleAddress: resource.moduleAddress || null, mode: resource.mode || 'managed',
    type, name, provider: resource.provider || providerFromType(type), category: Object.hasOwn(CATEGORY_META, resource.category) ? resource.category : classifyType(type),
    action: resource.action || 'present', attributes: redactKubernetesSecret(attrs), source: resource.source || { kind: 'normalized' }
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
  if (/db_|database|rds|dynamodb|elasticache|redis|postgres|mysql|aurora|sql|cloudsql/.test(t)) return 'data';
  if (/iam|policy|role|security_group|securitygroup|kms|secret|certificate|waf|acl|guardduty|service_account|serviceaccount|network_security_group/.test(t)) return 'security';
  if (/vpc|subnet|route|gateway|loadbalancer|load_balancer|\blb\b|listener|eip|firewall|network|vpn|dns|route53|ingress|service$/.test(t)) return 'network';
  if (/instance|launch|autoscaling|ecs|eks|lambda|function|container|node|compute|app_service|deployment|stateful_set|daemon_set|pod|job|cron_job/.test(t)) return 'compute';
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
