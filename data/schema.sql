PRAGMA journal_mode = DELETE;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS db_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS health_data_categories (
  category_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  sensitivity_tier TEXT NOT NULL CHECK (sensitivity_tier IN ('critical', 'high', 'moderate')),
  us_regimes TEXT NOT NULL,
  eu_regimes TEXT NOT NULL,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS medical_device_classification_rules (
  rule_id TEXT PRIMARY KEY,
  region TEXT NOT NULL CHECK (region IN ('US', 'EU')),
  framework TEXT NOT NULL,
  class_label TEXT NOT NULL,
  trigger_keywords TEXT NOT NULL,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS architecture_patterns (
  pattern_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  primary_system TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pattern_components (
  component_id TEXT PRIMARY KEY,
  pattern_id TEXT NOT NULL REFERENCES architecture_patterns(pattern_id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  component_type TEXT NOT NULL,
  description TEXT NOT NULL,
  trust_zone TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pattern_components_pattern
  ON pattern_components(pattern_id);

CREATE TABLE IF NOT EXISTS pattern_trust_boundaries (
  boundary_id TEXT PRIMARY KEY,
  pattern_id TEXT NOT NULL REFERENCES architecture_patterns(pattern_id) ON DELETE CASCADE,
  boundary_name TEXT NOT NULL,
  from_zone TEXT NOT NULL,
  to_zone TEXT NOT NULL,
  risk_note TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pattern_trust_boundaries_pattern
  ON pattern_trust_boundaries(pattern_id);

CREATE TABLE IF NOT EXISTS pattern_data_flows (
  flow_id TEXT PRIMARY KEY,
  pattern_id TEXT NOT NULL REFERENCES architecture_patterns(pattern_id) ON DELETE CASCADE,
  flow_name TEXT NOT NULL,
  source_component TEXT NOT NULL,
  target_component TEXT NOT NULL,
  data_categories TEXT NOT NULL,
  protocols TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pattern_data_flows_pattern
  ON pattern_data_flows(pattern_id);

CREATE TABLE IF NOT EXISTS pattern_weak_points (
  weak_point_id TEXT PRIMARY KEY,
  pattern_id TEXT NOT NULL REFERENCES architecture_patterns(pattern_id) ON DELETE CASCADE,
  weak_point TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'moderate', 'low')),
  rationale TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pattern_weak_points_pattern
  ON pattern_weak_points(pattern_id);

CREATE TABLE IF NOT EXISTS threat_scenarios (
  threat_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  pattern_id TEXT REFERENCES architecture_patterns(pattern_id),
  description TEXT NOT NULL,
  attack_path TEXT NOT NULL,
  clinical_impact TEXT NOT NULL,
  business_impact TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'moderate', 'low')),
  mitre_tactics TEXT NOT NULL,
  mitigations TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_scenarios_pattern
  ON threat_scenarios(pattern_id);

CREATE VIRTUAL TABLE IF NOT EXISTS threat_scenarios_fts USING fts5(
  threat_id,
  name,
  description,
  attack_path,
  clinical_impact,
  business_impact,
  content='threat_scenarios',
  content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS threat_scenarios_ai AFTER INSERT ON threat_scenarios BEGIN
  INSERT INTO threat_scenarios_fts(rowid, threat_id, name, description, attack_path, clinical_impact, business_impact)
  VALUES (new.rowid, new.threat_id, new.name, new.description, new.attack_path, new.clinical_impact, new.business_impact);
END;

CREATE TRIGGER IF NOT EXISTS threat_scenarios_ad AFTER DELETE ON threat_scenarios BEGIN
  INSERT INTO threat_scenarios_fts(threat_scenarios_fts, rowid, threat_id, name, description, attack_path, clinical_impact, business_impact)
  VALUES('delete', old.rowid, old.threat_id, old.name, old.description, old.attack_path, old.clinical_impact, old.business_impact);
END;

CREATE TRIGGER IF NOT EXISTS threat_scenarios_au AFTER UPDATE ON threat_scenarios BEGIN
  INSERT INTO threat_scenarios_fts(threat_scenarios_fts, rowid, threat_id, name, description, attack_path, clinical_impact, business_impact)
  VALUES('delete', old.rowid, old.threat_id, old.name, old.description, old.attack_path, old.clinical_impact, old.business_impact);
  INSERT INTO threat_scenarios_fts(rowid, threat_id, name, description, attack_path, clinical_impact, business_impact)
  VALUES (new.rowid, new.threat_id, new.name, new.description, new.attack_path, new.clinical_impact, new.business_impact);
END;

CREATE TABLE IF NOT EXISTS threat_regulation_links (
  threat_id TEXT NOT NULL REFERENCES threat_scenarios(threat_id) ON DELETE CASCADE,
  source_mcp TEXT NOT NULL,
  requirement_ref TEXT NOT NULL,
  obligation_summary TEXT NOT NULL,
  PRIMARY KEY (threat_id, source_mcp, requirement_ref)
);

CREATE TABLE IF NOT EXISTS threat_control_links (
  threat_id TEXT NOT NULL REFERENCES threat_scenarios(threat_id) ON DELETE CASCADE,
  control_framework TEXT NOT NULL,
  control_id TEXT NOT NULL,
  control_summary TEXT NOT NULL,
  PRIMARY KEY (threat_id, control_framework, control_id)
);

CREATE TABLE IF NOT EXISTS threat_expert_profiles (
  threat_id TEXT PRIMARY KEY REFERENCES threat_scenarios(threat_id) ON DELETE CASCADE,
  mitre_techniques TEXT NOT NULL,
  likelihood_factors TEXT NOT NULL,
  exploit_preconditions TEXT NOT NULL,
  detection_indicators TEXT NOT NULL,
  historical_incidents TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_response_playbooks (
  threat_id TEXT PRIMARY KEY REFERENCES threat_scenarios(threat_id) ON DELETE CASCADE,
  triage_priority TEXT NOT NULL CHECK (triage_priority IN ('P1', 'P2', 'P3')),
  immediate_containment_actions TEXT NOT NULL,
  clinical_safety_actions TEXT NOT NULL,
  forensic_artifacts TEXT NOT NULL,
  recovery_validation_checks TEXT NOT NULL,
  communication_requirements TEXT NOT NULL,
  escalation_routes TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS technical_standards (
  standard_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  authority TEXT NOT NULL,
  scope TEXT NOT NULL,
  version TEXT,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS standard_mappings (
  mapping_id TEXT PRIMARY KEY,
  input_type TEXT NOT NULL,
  input_id TEXT NOT NULL,
  standard_id TEXT NOT NULL REFERENCES technical_standards(standard_id),
  mapping_type TEXT NOT NULL,
  rationale TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_standard_mappings_input
  ON standard_mappings(input_type, input_id);

CREATE TABLE IF NOT EXISTS obligation_profiles (
  profile_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  conditions TEXT NOT NULL,
  priority TEXT NOT NULL CHECK (priority IN ('critical', 'high', 'moderate')),
  source_router TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jurisdiction_overlays (
  overlay_id TEXT PRIMARY KEY,
  country_code TEXT NOT NULL,
  role TEXT NOT NULL,
  system_type TEXT NOT NULL,
  data_type TEXT NOT NULL,
  requires_ai INTEGER NOT NULL DEFAULT 0,
  requires_medical_devices INTEGER NOT NULL DEFAULT 0,
  obligation_name TEXT NOT NULL,
  priority TEXT NOT NULL CHECK (priority IN ('critical', 'high', 'moderate')),
  source_router TEXT NOT NULL,
  regulation_refs TEXT NOT NULL,
  standard_refs TEXT NOT NULL,
  basis TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('authoritative', 'inferred', 'estimated'))
);

CREATE INDEX IF NOT EXISTS idx_jurisdiction_overlays_country
  ON jurisdiction_overlays(country_code);

CREATE TABLE IF NOT EXISTS breach_rules (
  rule_id TEXT PRIMARY KEY,
  jurisdiction TEXT NOT NULL,
  trigger_category TEXT NOT NULL,
  deadline_hours INTEGER NOT NULL,
  notify_parties TEXT NOT NULL,
  content_requirements TEXT NOT NULL,
  source_router TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_templates (
  template_id TEXT PRIMARY KEY,
  audit_type TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  artifacts TEXT NOT NULL,
  linked_standards TEXT NOT NULL,
  linked_controls TEXT NOT NULL
);
