import type Database from 'better-sqlite3';
import { parseJsonArray } from '../db.js';
import type { ClassifyMedicalDeviceInput, ToolError } from '../types.js';

type RuleRow = {
  rule_id: string;
  region: 'US' | 'EU';
  framework: string;
  class_label: string;
  trigger_keywords: string;
  notes: string | null;
};

function keywordHits(description: string, keywords: string[]): number {
  let score = 0;
  for (const keyword of keywords) {
    if (description.includes(keyword.toLowerCase())) {
      score += 1;
    }
  }
  return score;
}

function hasAny(description: string, values: string[]): boolean {
  return values.some((value) => description.includes(value.toLowerCase()));
}

function parseFdaClass(label: string | null): 'I' | 'II' | 'III' | null {
  if (!label) {
    return null;
  }
  const lowered = label.toLowerCase();
  if (lowered.includes('class iii') || lowered.includes('class 3')) {
    return 'III';
  }
  if (lowered.includes('class ii') || lowered.includes('class 2')) {
    return 'II';
  }
  if (lowered.includes('class i') || lowered.includes('class 1')) {
    return 'I';
  }
  return null;
}

function parseMdrClass(label: string | null): 'I' | 'IIa' | 'IIb' | 'III' | null {
  if (!label) {
    return null;
  }
  const lowered = label.toLowerCase();
  if (lowered.includes('iii') || lowered.includes('class 3')) {
    return 'III';
  }
  if (lowered.includes('iib') || lowered.includes('ii b')) {
    return 'IIb';
  }
  if (lowered.includes('iia') || lowered.includes('ii a')) {
    return 'IIa';
  }
  if (lowered.includes('class i') || lowered.includes('class 1') || lowered.includes(' i likely')) {
    return 'I';
  }
  return null;
}

function deriveImdrfCategory(signals: {
  drivesClinicalDecisions: boolean;
  lifeSustainingContext: boolean;
  activeMonitoring: boolean;
  informationalOnly: boolean;
}): 'I' | 'II' | 'III' | 'IV' | 'undetermined' {
  if (signals.lifeSustainingContext && signals.drivesClinicalDecisions) {
    return 'IV';
  }
  if (signals.drivesClinicalDecisions && signals.activeMonitoring) {
    return 'III';
  }
  if (signals.drivesClinicalDecisions) {
    return 'II';
  }
  if (signals.informationalOnly) {
    return 'I';
  }
  return 'undetermined';
}

export function classifyMedicalDevice(
  db: Database.Database,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = args as ClassifyMedicalDeviceInput & {
    device_description?: string;
    software_function?: string;
    clinical_purpose?: string;
    data_types?: string[];
  };
  const description = input.description ??
    [input.device_description, input.software_function, input.clinical_purpose, (input.data_types ?? []).join(' ')]
      .filter(Boolean)
      .join(' ')
      .trim();

  if (!description || description.trim().length < 10) {
    return {
      error: 'description must be provided and include intended clinical function',
      hint: 'Include who uses the product, whether it drives diagnosis/therapy, and whether outputs are patient-specific.',
    };
  }

  const region = input.region ?? 'US_EU';
  const loweredDescription = description.toLowerCase();
  const isAdministrativeOnly = hasAny(loweredDescription, [
    'administrative only',
    'billing',
    'scheduling',
    'claims processing',
  ]);
  const hasAiMl = hasAny(loweredDescription, ['ai', 'machine learning', 'ml model', 'algorithmic']);
  const drivesClinicalDecisions = hasAny(loweredDescription, [
    'diagnostic',
    'diagnosis',
    'therapy',
    'treatment',
    'clinical decision support',
    'triage',
    'patient-specific',
  ]);
  const lifeSustainingContext = hasAny(loweredDescription, [
    'life sustaining',
    'life-support',
    'critical condition',
    'implantable',
    'ventilator',
    'defibrillator',
    'autonomous dosing',
  ]);
  const activeMonitoring = hasAny(loweredDescription, [
    'active monitoring',
    'vital signs',
    'physiological monitoring',
    'icu',
    'alarm',
  ]);
  const isSoftwareFunction = hasAny(loweredDescription, [
    'software',
    'saas',
    'algorithm',
    'model',
    'api',
    'application',
    'samd',
  ]);

  const rows = db
    .prepare(`
      SELECT rule_id, region, framework, class_label, trigger_keywords, notes
      FROM medical_device_classification_rules
      ORDER BY region, rule_id
    `)
    .all() as RuleRow[];

  const filteredByRegion = rows.filter((row) => region === 'US_EU' || row.region === region);
  const scored = filteredByRegion
    .map((row) => {
      const keywords = parseJsonArray(row.trigger_keywords);
      return {
        ...row,
        keywords,
        score: keywordHits(loweredDescription, keywords),
      };
    })
    .filter((row) => row.score > 0)
    .sort((a, b) => b.score - a.score);

  const byRegion = new Map<'US' | 'EU', (typeof scored)[number]>();
  for (const candidate of scored) {
    if (!byRegion.has(candidate.region)) {
      byRegion.set(candidate.region, candidate);
    }
  }

  const top = scored[0] ?? null;
  const topUs = byRegion.get('US') ?? null;
  const topEu = byRegion.get('EU') ?? null;
  const fdaClass = parseFdaClass(topUs?.class_label ?? null);
  const mdrClass = parseMdrClass(topEu?.class_label ?? null);
  const inferredFdaClass: 'I' | 'II' | 'III' | null = fdaClass ??
    (isAdministrativeOnly
      ? null
      : lifeSustainingContext && drivesClinicalDecisions
        ? 'III'
        : drivesClinicalDecisions || activeMonitoring
          ? 'II'
          : 'I');
  const inferredMdrClass: 'I' | 'IIa' | 'IIb' | 'III' | null = mdrClass ??
    (isAdministrativeOnly
      ? null
      : lifeSustainingContext && drivesClinicalDecisions
        ? 'III'
        : drivesClinicalDecisions && activeMonitoring
          ? 'IIb'
          : drivesClinicalDecisions
            ? 'IIa'
            : 'I');
  const imdrfCategory = deriveImdrfCategory({
    drivesClinicalDecisions,
    lifeSustainingContext,
    activeMonitoring,
    informationalOnly: !drivesClinicalDecisions && !lifeSustainingContext && !activeMonitoring,
  });
  const samdLikely =
    !isAdministrativeOnly &&
    (isSoftwareFunction || drivesClinicalDecisions || hasAiMl || loweredDescription.includes('samd'));
  const aiActHighRiskLikely = hasAiMl && (drivesClinicalDecisions || lifeSustainingContext);

  const defaultResult = {
    classification: 'Insufficient detail for deterministic class assignment',
    confidence: 'low',
    note: 'Run manual regulatory determination with intended use, indications, and claim language.',
  };

  const standardsHint = new Set<string>(['iso_14971']);
  if (samdLikely || isSoftwareFunction || drivesClinicalDecisions) {
    standardsHint.add('iec_62304');
  }
  if (activeMonitoring || lifeSustainingContext) {
    standardsHint.add('iec_80001_1');
  }
  if (region === 'US' || region === 'US_EU') {
    standardsHint.add('fda_premarket_cyber_2023');
    standardsHint.add('nist_sp_800_66');
  }
  if (region === 'EU' || region === 'US_EU') {
    standardsHint.add('mdcg_2019_16');
  }
  if (drivesClinicalDecisions || aiActHighRiskLikely) {
    standardsHint.add('iso_27799');
  }

  return {
    input_summary: description,
    region,
    primary_result: top
      ? {
          rule_id: top.rule_id,
          framework: top.framework,
          region: top.region,
          class_label: top.class_label,
          matched_keywords: top.keywords.filter((keyword) => loweredDescription.includes(keyword.toLowerCase())),
          notes: top.notes,
          confidence: top.score >= 2 ? 'medium' : 'low',
        }
      : defaultResult,
    candidate_rules: scored.map((row) => ({
      rule_id: row.rule_id,
      framework: row.framework,
      region: row.region,
      class_label: row.class_label,
      score: row.score,
    })),
    risk_signals: {
      administrative_only_signal: isAdministrativeOnly,
      software_function_signal: isSoftwareFunction,
      ai_ml_signal: hasAiMl,
      drives_clinical_decisions_signal: drivesClinicalDecisions,
      active_monitoring_signal: activeMonitoring,
      life_sustaining_signal: lifeSustainingContext,
    },
    fda_classification: {
      class: inferredFdaClass,
      basis: topUs ? topUs.class_label : null,
      confidence: topUs ? (topUs.score >= 2 ? 'medium' : 'low') : 'low',
      likely_pathway:
        inferredFdaClass === 'III'
          ? 'PMA'
          : inferredFdaClass === 'II'
            ? '510(k) or De Novo (product-dependent)'
            : inferredFdaClass === 'I'
              ? 'General controls / possible exemption'
              : 'manual_determination_required',
    },
    mdr_classification: {
      class: inferredMdrClass,
      basis: topEu ? topEu.class_label : null,
      confidence: topEu ? (topEu.score >= 2 ? 'medium' : 'low') : 'low',
      likely_pathway:
        inferredMdrClass === 'III'
          ? 'Notified Body + highest-risk conformity assessment'
          : inferredMdrClass === 'IIb'
            ? 'Notified Body conformity assessment'
            : inferredMdrClass === 'IIa'
              ? 'Notified Body review with moderate/high-risk controls'
              : inferredMdrClass === 'I'
                ? 'Class I route (with software Rule 11 confirmation)'
                : 'manual_determination_required',
    },
    samd_determination: {
      likely_samd: samdLikely,
      rationale: samdLikely
        ? 'Software or algorithmic function appears to influence diagnosis, treatment, or patient-specific decisions.'
        : 'Description appears administrative or lacks medical intended-use claims.',
      imdrf_category: imdrfCategory,
    },
    ai_act_considerations: {
      high_risk_likelihood: aiActHighRiskLikely,
      basis: aiActHighRiskLikely
        ? ['AI/ML signal present', 'Clinical decision/therapy impact signal present']
        : ['No strong high-risk health-AI signal from provided text'],
      route: aiActHighRiskLikely ? 'EU_Regulations_MCP:AI_ACT_ANNEX_III_HEALTH' : null,
    },
    recommended_standards: [...standardsHint],
    applicable_standards: [...standardsHint],
    pathway: top?.framework ?? 'manual_determination_required',
    fda_class: inferredFdaClass,
    mdr_class: inferredMdrClass,
    samd_category: samdLikely ? imdrfCategory : null,
    pathway_summary: {
      us_pathway: topUs?.framework ?? 'manual',
      eu_pathway: topEu?.framework ?? 'manual',
      next_steps: [
        'Confirm intended use, indications, and clinical claim language with regulatory counsel.',
        'Run map_to_healthcare_standards for IEC 62304/ISO 14971/IEC 80001-1 implementation mapping.',
        'Validate final class and submission route against authoritative FDA/EU MDR sources.',
      ],
    },
    external_resolution_routes: {
      US: ['US_Regulations_MCP:FDA_524B', 'US-law-mcp:medical_device_state_overlays'],
      EU: ['EU_Regulations_MCP:MDR_IVDR', 'EU_Regulations_MCP:AI_ACT'],
    },
  };
}
