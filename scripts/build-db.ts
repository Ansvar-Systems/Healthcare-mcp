#!/usr/bin/env tsx

import Database from 'better-sqlite3';
import { existsSync, mkdirSync, readFileSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

type HealthDataCategory = {
  category_id: string;
  name: string;
  description: string;
  sensitivity_tier: 'critical' | 'high' | 'moderate';
  us_regimes: string[];
  eu_regimes: string[];
  notes?: string;
};

type DeviceRule = {
  rule_id: string;
  region: 'US' | 'EU';
  framework: string;
  class_label: string;
  trigger_keywords: string[];
  notes?: string;
};

type ArchitecturePatternSeed = {
  pattern: {
    pattern_id: string;
    name: string;
    description: string;
    primary_system: string;
  };
  components: Array<{
    component_id: string;
    name: string;
    component_type: string;
    description: string;
    trust_zone: string;
  }>;
  trust_boundaries: Array<{
    boundary_id: string;
    boundary_name: string;
    from_zone: string;
    to_zone: string;
    risk_note: string;
  }>;
  data_flows: Array<{
    flow_id: string;
    flow_name: string;
    source_component: string;
    target_component: string;
    data_categories: string[];
    protocols: string[];
  }>;
  weak_points: Array<{
    weak_point_id: string;
    weak_point: string;
    severity: 'critical' | 'high' | 'moderate' | 'low';
    rationale: string;
  }>;
};

type ThreatScenario = {
  threat_id: string;
  name: string;
  pattern_id: string | null;
  description: string;
  attack_path: string;
  clinical_impact: string;
  business_impact: string;
  severity: 'critical' | 'high' | 'moderate' | 'low';
  mitre_tactics: string[];
  mitigations: string[];
};

type ThreatLinks = {
  regulation_links: Array<{
    threat_id: string;
    source_mcp: string;
    requirement_ref: string;
    obligation_summary: string;
  }>;
  control_links: Array<{
    threat_id: string;
    control_framework: string;
    control_id: string;
    control_summary: string;
  }>;
};

type ThreatExpertProfile = {
  threat_id: string;
  mitre_techniques: string[];
  likelihood_factors: string[];
  exploit_preconditions: string[];
  detection_indicators: string[];
  historical_incidents: string[];
};

type ThreatResponsePlaybook = {
  threat_id: string;
  triage_priority: 'P1' | 'P2' | 'P3';
  immediate_containment_actions: string[];
  clinical_safety_actions: string[];
  forensic_artifacts: string[];
  recovery_validation_checks: string[];
  communication_requirements: string[];
  escalation_routes: string[];
};

type TechnicalStandardsSeed = {
  standards: Array<{
    standard_id: string;
    name: string;
    authority: string;
    scope: string;
    version?: string;
    status: string;
  }>;
  mappings: Array<{
    mapping_id: string;
    input_type: string;
    input_id: string;
    standard_id: string;
    mapping_type: string;
    rationale: string;
  }>;
};

type ObligationProfile = {
  profile_id: string;
  name: string;
  jurisdiction: string;
  entity_type: string;
  conditions: string[];
  priority: 'critical' | 'high' | 'moderate';
  source_router: string;
};

type JurisdictionOverlay = {
  overlay_id: string;
  country_code: string;
  role: string;
  system_type: string;
  data_type: string;
  requires_ai: number;
  requires_medical_devices: number;
  obligation_name: string;
  priority: 'critical' | 'high' | 'moderate';
  source_router: string;
  regulation_refs: string[];
  standard_refs: string[];
  basis: string;
  confidence: 'authoritative' | 'inferred' | 'estimated';
};

type BreachRule = {
  rule_id: string;
  jurisdiction: string;
  trigger_category: string;
  deadline_hours: number;
  notify_parties: string[];
  content_requirements: string[];
  source_router: string;
};

type EvidenceTemplate = {
  template_id: string;
  audit_type: string;
  name: string;
  description: string;
  artifacts: string[];
  linked_standards: string[];
  linked_controls: string[];
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = join(__dirname, '..');
const DATA_DIR = join(ROOT, 'data');
const SEED_DIR = join(DATA_DIR, 'seed');
const DB_PATH = join(DATA_DIR, 'healthcare.db');
const SCHEMA_PATH = join(DATA_DIR, 'schema.sql');

function readJsonFile<T>(filename: string): T {
  const fullPath = join(SEED_DIR, filename);
  return JSON.parse(readFileSync(fullPath, 'utf-8')) as T;
}

function setMetadata(db: Database.Database): void {
  const put = db.prepare('INSERT OR REPLACE INTO db_metadata (key, value) VALUES (?, ?)');
  const now = new Date().toISOString();
  const entries: Array<[string, string]> = [
    ['schema_version', '0.1.0'],
    ['dataset_name', 'healthcare_domain_intelligence'],
    ['coverage_regions', 'US,EU'],
    ['transport_model', 'router_with_external_mcp_dependencies'],
    ['tier', 'foundation'],
    ['built_at', now],
    ['last_source_check', now],
  ];

  for (const [key, value] of entries) {
    put.run(key, value);
  }
}

function loadHealthDataCategories(db: Database.Database): void {
  const items = readJsonFile<HealthDataCategory[]>('health_data_categories.json');
  const insert = db.prepare(`
    INSERT INTO health_data_categories (
      category_id, name, description, sensitivity_tier, us_regimes, eu_regimes, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const item of items) {
    insert.run(
      item.category_id,
      item.name,
      item.description,
      item.sensitivity_tier,
      JSON.stringify(item.us_regimes),
      JSON.stringify(item.eu_regimes),
      item.notes ?? null,
    );
  }
}

function loadMedicalDeviceRules(db: Database.Database): void {
  const items = readJsonFile<DeviceRule[]>('medical_device_rules.json');
  const insert = db.prepare(`
    INSERT INTO medical_device_classification_rules (
      rule_id, region, framework, class_label, trigger_keywords, notes
    ) VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const item of items) {
    insert.run(
      item.rule_id,
      item.region,
      item.framework,
      item.class_label,
      JSON.stringify(item.trigger_keywords),
      item.notes ?? null,
    );
  }
}

function loadArchitecturePatterns(db: Database.Database): void {
  const items = readJsonFile<ArchitecturePatternSeed[]>('architecture_patterns.json');
  const insertPattern = db.prepare(`
    INSERT INTO architecture_patterns (pattern_id, name, description, primary_system)
    VALUES (?, ?, ?, ?)
  `);
  const insertComponent = db.prepare(`
    INSERT INTO pattern_components (component_id, pattern_id, name, component_type, description, trust_zone)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const insertBoundary = db.prepare(`
    INSERT INTO pattern_trust_boundaries (boundary_id, pattern_id, boundary_name, from_zone, to_zone, risk_note)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const insertFlow = db.prepare(`
    INSERT INTO pattern_data_flows (flow_id, pattern_id, flow_name, source_component, target_component, data_categories, protocols)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const insertWeakPoint = db.prepare(`
    INSERT INTO pattern_weak_points (weak_point_id, pattern_id, weak_point, severity, rationale)
    VALUES (?, ?, ?, ?, ?)
  `);

  for (const item of items) {
    insertPattern.run(
      item.pattern.pattern_id,
      item.pattern.name,
      item.pattern.description,
      item.pattern.primary_system,
    );

    for (const component of item.components) {
      insertComponent.run(
        component.component_id,
        item.pattern.pattern_id,
        component.name,
        component.component_type,
        component.description,
        component.trust_zone,
      );
    }

    for (const boundary of item.trust_boundaries) {
      insertBoundary.run(
        boundary.boundary_id,
        item.pattern.pattern_id,
        boundary.boundary_name,
        boundary.from_zone,
        boundary.to_zone,
        boundary.risk_note,
      );
    }

    for (const flow of item.data_flows) {
      insertFlow.run(
        flow.flow_id,
        item.pattern.pattern_id,
        flow.flow_name,
        flow.source_component,
        flow.target_component,
        JSON.stringify(flow.data_categories),
        JSON.stringify(flow.protocols),
      );
    }

    for (const weakPoint of item.weak_points) {
      insertWeakPoint.run(
        weakPoint.weak_point_id,
        item.pattern.pattern_id,
        weakPoint.weak_point,
        weakPoint.severity,
        weakPoint.rationale,
      );
    }
  }
}

function loadThreats(db: Database.Database): void {
  const threats = readJsonFile<ThreatScenario[]>('threat_scenarios.json');
  const links = readJsonFile<ThreatLinks>('threat_links.json');
  const expertProfiles = readJsonFile<ThreatExpertProfile[]>('threat_expert_profiles.json');
  const responsePlaybooks = readJsonFile<ThreatResponsePlaybook[]>('threat_response_playbooks.json');

  const insertThreat = db.prepare(`
    INSERT INTO threat_scenarios (
      threat_id, name, pattern_id, description, attack_path, clinical_impact, business_impact,
      severity, mitre_tactics, mitigations
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const threat of threats) {
    insertThreat.run(
      threat.threat_id,
      threat.name,
      threat.pattern_id,
      threat.description,
      threat.attack_path,
      threat.clinical_impact,
      threat.business_impact,
      threat.severity,
      JSON.stringify(threat.mitre_tactics),
      JSON.stringify(threat.mitigations),
    );
  }

  const insertRegLink = db.prepare(`
    INSERT INTO threat_regulation_links (threat_id, source_mcp, requirement_ref, obligation_summary)
    VALUES (?, ?, ?, ?)
  `);

  for (const link of links.regulation_links) {
    insertRegLink.run(
      link.threat_id,
      link.source_mcp,
      link.requirement_ref,
      link.obligation_summary,
    );
  }

  const insertControlLink = db.prepare(`
    INSERT INTO threat_control_links (threat_id, control_framework, control_id, control_summary)
    VALUES (?, ?, ?, ?)
  `);

  for (const link of links.control_links) {
    insertControlLink.run(
      link.threat_id,
      link.control_framework,
      link.control_id,
      link.control_summary,
    );
  }

  const insertExpertProfile = db.prepare(`
    INSERT INTO threat_expert_profiles (
      threat_id, mitre_techniques, likelihood_factors, exploit_preconditions,
      detection_indicators, historical_incidents
    ) VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const profile of expertProfiles) {
    insertExpertProfile.run(
      profile.threat_id,
      JSON.stringify(profile.mitre_techniques),
      JSON.stringify(profile.likelihood_factors),
      JSON.stringify(profile.exploit_preconditions),
      JSON.stringify(profile.detection_indicators),
      JSON.stringify(profile.historical_incidents),
    );
  }

  const insertPlaybook = db.prepare(`
    INSERT INTO threat_response_playbooks (
      threat_id, triage_priority, immediate_containment_actions, clinical_safety_actions,
      forensic_artifacts, recovery_validation_checks, communication_requirements, escalation_routes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const playbook of responsePlaybooks) {
    insertPlaybook.run(
      playbook.threat_id,
      playbook.triage_priority,
      JSON.stringify(playbook.immediate_containment_actions),
      JSON.stringify(playbook.clinical_safety_actions),
      JSON.stringify(playbook.forensic_artifacts),
      JSON.stringify(playbook.recovery_validation_checks),
      JSON.stringify(playbook.communication_requirements),
      JSON.stringify(playbook.escalation_routes),
    );
  }
}

function loadTechnicalStandards(db: Database.Database): void {
  const payload = readJsonFile<TechnicalStandardsSeed>('technical_standards.json');

  const insertStandard = db.prepare(`
    INSERT INTO technical_standards (standard_id, name, authority, scope, version, status)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const standard of payload.standards) {
    insertStandard.run(
      standard.standard_id,
      standard.name,
      standard.authority,
      standard.scope,
      standard.version ?? null,
      standard.status,
    );
  }

  const insertMapping = db.prepare(`
    INSERT INTO standard_mappings (mapping_id, input_type, input_id, standard_id, mapping_type, rationale)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const mapping of payload.mappings) {
    insertMapping.run(
      mapping.mapping_id,
      mapping.input_type,
      mapping.input_id,
      mapping.standard_id,
      mapping.mapping_type,
      mapping.rationale,
    );
  }
}

function loadObligationProfiles(db: Database.Database): void {
  const profiles = readJsonFile<ObligationProfile[]>('obligation_profiles.json');
  const insert = db.prepare(`
    INSERT INTO obligation_profiles (
      profile_id, name, jurisdiction, entity_type, conditions, priority, source_router
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const profile of profiles) {
    insert.run(
      profile.profile_id,
      profile.name,
      profile.jurisdiction,
      profile.entity_type,
      JSON.stringify(profile.conditions),
      profile.priority,
      profile.source_router,
    );
  }
}

function loadJurisdictionOverlays(db: Database.Database): void {
  const overlays = readJsonFile<JurisdictionOverlay[]>('jurisdiction_overlays.json');
  const insert = db.prepare(`
    INSERT INTO jurisdiction_overlays (
      overlay_id, country_code, role, system_type, data_type, requires_ai,
      requires_medical_devices, obligation_name, priority, source_router,
      regulation_refs, standard_refs, basis, confidence
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const overlay of overlays) {
    insert.run(
      overlay.overlay_id,
      overlay.country_code,
      overlay.role,
      overlay.system_type,
      overlay.data_type,
      overlay.requires_ai,
      overlay.requires_medical_devices,
      overlay.obligation_name,
      overlay.priority,
      overlay.source_router,
      JSON.stringify(overlay.regulation_refs),
      JSON.stringify(overlay.standard_refs),
      overlay.basis,
      overlay.confidence,
    );
  }
}

function loadBreachRules(db: Database.Database): void {
  const rules = readJsonFile<BreachRule[]>('breach_rules.json');
  const insert = db.prepare(`
    INSERT INTO breach_rules (
      rule_id, jurisdiction, trigger_category, deadline_hours, notify_parties, content_requirements, source_router
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const rule of rules) {
    insert.run(
      rule.rule_id,
      rule.jurisdiction,
      rule.trigger_category,
      rule.deadline_hours,
      JSON.stringify(rule.notify_parties),
      JSON.stringify(rule.content_requirements),
      rule.source_router,
    );
  }
}

function loadEvidenceTemplates(db: Database.Database): void {
  const templates = readJsonFile<EvidenceTemplate[]>('evidence_templates.json');
  const insert = db.prepare(`
    INSERT INTO evidence_templates (
      template_id, audit_type, name, description, artifacts, linked_standards, linked_controls
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const template of templates) {
    insert.run(
      template.template_id,
      template.audit_type,
      template.name,
      template.description,
      JSON.stringify(template.artifacts),
      JSON.stringify(template.linked_standards),
      JSON.stringify(template.linked_controls),
    );
  }
}

function main(): void {
  mkdirSync(DATA_DIR, { recursive: true });

  if (existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
  }

  const db = new Database(DB_PATH);
  const schema = readFileSync(SCHEMA_PATH, 'utf-8');
  db.exec(schema);

  const transaction = db.transaction(() => {
    setMetadata(db);
    loadHealthDataCategories(db);
    loadMedicalDeviceRules(db);
    loadArchitecturePatterns(db);
    loadThreats(db);
    loadTechnicalStandards(db);
    loadObligationProfiles(db);
    loadJurisdictionOverlays(db);
    loadBreachRules(db);
    loadEvidenceTemplates(db);
  });

  transaction();

  const counts = {
    categories: db.prepare('SELECT COUNT(*) as count FROM health_data_categories').get() as { count: number },
    patterns: db.prepare('SELECT COUNT(*) as count FROM architecture_patterns').get() as { count: number },
    threats: db.prepare('SELECT COUNT(*) as count FROM threat_scenarios').get() as { count: number },
    standards: db.prepare('SELECT COUNT(*) as count FROM technical_standards').get() as { count: number },
    obligations: db.prepare('SELECT COUNT(*) as count FROM obligation_profiles').get() as { count: number },
    overlays: db.prepare('SELECT COUNT(*) as count FROM jurisdiction_overlays').get() as { count: number },
    threatExpertProfiles: db
      .prepare('SELECT COUNT(*) as count FROM threat_expert_profiles')
      .get() as { count: number },
    threatResponsePlaybooks: db
      .prepare('SELECT COUNT(*) as count FROM threat_response_playbooks')
      .get() as { count: number },
  };

  console.log('✅ healthcare.db built successfully');
  console.log(`   categories: ${counts.categories.count}`);
  console.log(`   patterns:   ${counts.patterns.count}`);
  console.log(`   threats:    ${counts.threats.count}`);
  console.log(`   standards:  ${counts.standards.count}`);
  console.log(`   obligations:${counts.obligations.count}`);
  console.log(`   overlays:   ${counts.overlays.count}`);
  console.log(`   threat_exp: ${counts.threatExpertProfiles.count}`);
  console.log(`   playbooks:  ${counts.threatResponsePlaybooks.count}`);

  db.close();
}

main();
