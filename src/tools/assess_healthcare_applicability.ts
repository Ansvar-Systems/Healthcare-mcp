import type { SqlDatabase } from '../db.js';
import { parseJsonArray } from '../db.js';
import {
  countryCodeFromUsJurisdiction,
  isEuJurisdiction,
  isUsJurisdiction,
  jurisdictionFamily,
  normalizeJurisdictionCode,
} from '../jurisdictions.js';
import type { AssessHealthcareApplicabilityInput, ToolError } from '../types.js';
import { resolveApplicabilityConflicts } from './applicability_conflicts.js';

type ObligationRow = {
  profile_id: string;
  name: string;
  jurisdiction: string;
  entity_type: string;
  conditions: string;
  priority: 'critical' | 'high' | 'moderate';
  source_router: string;
};

type OverlayRow = {
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
  regulation_refs: string;
  standard_refs: string;
  basis: string;
  confidence: 'authoritative' | 'inferred' | 'estimated';
};

type ApplicabilityObligation = {
  obligation_id: string;
  profile_id?: string;
  name: string;
  jurisdiction: string;
  priority: 'critical' | 'high' | 'moderate';
  conditions: string[];
  source_router: string;
  regulation_refs: string[];
  standard_refs: string[];
  confidence: 'authoritative' | 'inferred' | 'estimated';
  basis: string;
  regulation_id: string | null;
  standard_id: string | null;
  overlay?: boolean;
  synthesized?: boolean;
};

type DomainFlags = {
  has_medical_devices: boolean;
  uses_ai_for_clinical_decisions: boolean;
  high_sensitivity_data: boolean;
};

type ContractingObligation = {
  agreement_type:
    | 'BAA'
    | 'DPA'
    | 'SUBPROCESSOR_FLOW_DOWN'
    | 'SCC_OR_EQUIVALENT_TRANSFER_MECHANISM'
    | 'PART2_REDISCLOSURE_CHAIN'
    | 'EHDS_SECONDARY_USE_PERMIT';
  applies: boolean;
  priority: 'critical' | 'high' | 'moderate';
  confidence: 'authoritative' | 'inferred' | 'estimated';
  rationale: string;
  source_router: string;
  trigger_conditions: string[];
};

function parseCountryCode(input?: string): string | null {
  if (!input || input.trim().length === 0) {
    return null;
  }

  return normalizeJurisdictionCode(input);
}

function parseCountryCodes(inputCountry: string | undefined, contextCountries: string[] | undefined): string[] {
  const parsed: string[] = [];

  if (inputCountry) {
    for (const part of inputCountry.split(',')) {
      const normalized = parseCountryCode(part);
      if (normalized) {
        parsed.push(normalized);
      }
    }
  }

  for (const country of contextCountries ?? []) {
    const normalized = parseCountryCode(country);
    if (normalized) {
      parsed.push(normalized);
    }
  }

  return [...new Set(parsed)];
}

function countryToJurisdiction(countryCode: string | null): string[] {
  if (!countryCode) {
    return [];
  }

  if (isUsJurisdiction(countryCode)) {
    return ['US'];
  }

  if (isEuJurisdiction(countryCode)) {
    return ['EU'];
  }

  return [countryCode];
}

function refsFromRouter(sourceRouter: string): string[] {
  const parts = sourceRouter.split('+').map((part) => part.trim()).filter(Boolean);
  const refs: string[] = [];

  for (const part of parts) {
    if (part.includes(':')) {
      refs.push(part.split(':').slice(1).join(':'));
    }
  }

  return refs;
}

function normalizeTokenSet(values: string[]): Set<string> {
  return new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean));
}

function includesMedicalDeviceSystem(systemTypes: Set<string>): boolean {
  for (const systemType of systemTypes) {
    if (systemType.includes('medical_device') || systemType.includes('samd') || systemType.includes('iomt')) {
      return true;
    }
  }
  return false;
}

function buildContractingObligations(
  jurisdictions: Set<string>,
  dataTypes: Set<string>,
  flags: DomainFlags,
): ContractingObligation[] {
  const hasUs = [...jurisdictions].some((jurisdiction) => isUsJurisdiction(jurisdiction));
  const hasEu = [...jurisdictions].some((jurisdiction) => isEuJurisdiction(jurisdiction));

  const hasHealthData =
    flags.high_sensitivity_data ||
    dataTypes.has('health_data') ||
    dataTypes.has('ephi') ||
    dataTypes.has('mental_health') ||
    dataTypes.has('genetic_data');
  const hasPart2 = dataTypes.has('part2_substance_use');
  const hasEhdsSecondary = dataTypes.has('ehds_secondary_use') || dataTypes.has('genomic_biobank_data');

  const obligations: ContractingObligation[] = [];

  obligations.push({
    agreement_type: 'BAA',
    applies: hasUs && hasHealthData,
    priority: 'critical',
    confidence: 'inferred',
    rationale:
      'US healthcare data processing chains commonly require covered-entity/business-associate contractual controls.',
    source_router: 'US_Regulations_MCP:HIPAA_BAA',
    trigger_conditions: ['US jurisdiction context', 'health data handled by external processors/subcontractors'],
  });

  obligations.push({
    agreement_type: 'DPA',
    applies: hasEu && hasHealthData,
    priority: 'critical',
    confidence: 'inferred',
    rationale: 'EU healthcare processing generally requires controller-processor contractual allocation and governance.',
    source_router: 'EU_Regulations_MCP:GDPR_CONTROLLER_PROCESSOR',
    trigger_conditions: ['EU jurisdiction context', 'special-category health data processing'],
  });

  obligations.push({
    agreement_type: 'SUBPROCESSOR_FLOW_DOWN',
    applies: (hasUs || hasEu) && hasHealthData,
    priority: 'high',
    confidence: 'estimated',
    rationale:
      'Healthcare data subcontracting chains require explicit downstream flow-down of security/privacy obligations.',
    source_router: 'US_Regulations_MCP:HIPAA_BAA + EU_Regulations_MCP:GDPR_ART_28',
    trigger_conditions: ['third-party or subcontractor chain present', 'regulated healthcare data'],
  });

  obligations.push({
    agreement_type: 'SCC_OR_EQUIVALENT_TRANSFER_MECHANISM',
    applies: hasUs && hasEu && hasHealthData,
    priority: 'high',
    confidence: 'estimated',
    rationale:
      'Cross-border US/EU healthcare data transfers usually require transfer mechanisms and supplementary safeguards.',
    source_router: 'EU_Regulations_MCP:GDPR_CHAPTER_V + EU-law-mcp:member_state_transfer_overlays',
    trigger_conditions: ['US and EU processing footprint', 'cross-border healthcare data transfers'],
  });

  obligations.push({
    agreement_type: 'PART2_REDISCLOSURE_CHAIN',
    applies: hasUs && hasPart2,
    priority: 'critical',
    confidence: 'inferred',
    rationale:
      'Substance-use records introduce heightened redisclosure restrictions in contractual and operational chains.',
    source_router: 'US_Regulations_MCP:42_CFR_PART_2',
    trigger_conditions: ['part2_substance_use data category detected'],
  });

  obligations.push({
    agreement_type: 'EHDS_SECONDARY_USE_PERMIT',
    applies: hasEu && hasEhdsSecondary,
    priority: 'high',
    confidence: 'estimated',
    rationale:
      'EHDS secondary-use scenarios may require permit and access-governance constraints beyond baseline GDPR controls.',
    source_router: 'EU_Regulations_MCP:EHDS_SECONDARY_USE',
    trigger_conditions: ['EU context', 'EHDS secondary-use or genomic-biobank data category'],
  });

  return obligations;
}

function buildSynthesizedCountryObligations(
  countryCode: string,
  entityType: string,
  domainFlags: DomainFlags,
): ApplicabilityObligation[] {
  const family = jurisdictionFamily(countryCode);
  const obligations: ApplicabilityObligation[] = [];
  const stateCode = countryCodeFromUsJurisdiction(countryCode);

  if (family === 'US') {
    obligations.push({
      obligation_id: `synth_${countryCode.toLowerCase().replace('-', '_')}_hipaa`,
      name: 'HIPAA security safeguards for healthcare systems',
      jurisdiction: countryCode,
      priority: 'critical',
      conditions: [`role=${entityType}`, 'coverage_mode=synthesized_us'],
      source_router: 'US_Regulations_MCP:HIPAA_164.312',
      regulation_refs: ['HIPAA_164.312'],
      standard_refs: ['NIST_SP_800_66'],
      confidence: 'inferred',
      basis:
        'US healthcare handling regulated patient information generally requires HIPAA safeguard alignment.',
      regulation_id: 'HIPAA_164.312',
      standard_id: 'NIST_SP_800_66',
      synthesized: true,
    });

    obligations.push({
      obligation_id: `synth_${countryCode.toLowerCase().replace('-', '_')}_state_law`,
      name: 'US state healthcare privacy and breach-law overlay',
      jurisdiction: countryCode,
      priority: 'high',
      conditions: [`role=${entityType}`, 'coverage_mode=synthesized_us'],
      source_router: 'US-law-mcp:state_health_privacy',
      regulation_refs: [stateCode ? `${stateCode}_HEALTH_PRIVACY` : 'US_STATE_HEALTH_PRIVACY'],
      standard_refs: [],
      confidence: 'estimated',
      basis:
        'US state healthcare privacy and breach rules vary; route to US law MCP for authoritative state provisions.',
      regulation_id: stateCode ? `${stateCode}_HEALTH_PRIVACY` : 'US_STATE_HEALTH_PRIVACY',
      standard_id: null,
      synthesized: true,
    });

    if (domainFlags.has_medical_devices || domainFlags.uses_ai_for_clinical_decisions) {
      obligations.push({
        obligation_id: `synth_${countryCode.toLowerCase().replace('-', '_')}_fda_524b`,
        name: 'FDA medical-device cybersecurity and SaMD pathway checks',
        jurisdiction: countryCode,
        priority: domainFlags.has_medical_devices ? 'critical' : 'high',
        conditions: [`role=${entityType}`, 'coverage_mode=synthesized_us'],
        source_router: 'US_Regulations_MCP:FDA_524B',
        regulation_refs: ['FDA_524B'],
        standard_refs: ['IEC_62304', 'ISO_14971'],
        confidence: 'inferred',
        basis:
          'US device and AI-enabled clinical software contexts commonly require FDA cybersecurity/SaMD pathway validation.',
        regulation_id: 'FDA_524B',
        standard_id: 'IEC_62304',
        synthesized: true,
      });
    }
  }

  if (family === 'EU') {
    obligations.push({
      obligation_id: `synth_${countryCode.toLowerCase()}_gdpr_art9`,
      name: 'GDPR special-category health data obligations',
      jurisdiction: countryCode,
      priority: 'critical',
      conditions: [`role=${entityType}`, 'coverage_mode=synthesized_eu'],
      source_router: 'EU_Regulations_MCP:GDPR_ART_9',
      regulation_refs: ['GDPR_ART_9'],
      standard_refs: ['ISO_27799'],
      confidence: 'authoritative',
      basis:
        'EU healthcare processing of patient data is generally special-category processing under GDPR Article 9.',
      regulation_id: 'GDPR_ART_9',
      standard_id: 'ISO_27799',
      synthesized: true,
    });

    obligations.push({
      obligation_id: `synth_${countryCode.toLowerCase()}_nis2`,
      name: 'NIS2 healthcare cybersecurity risk management overlay',
      jurisdiction: countryCode,
      priority: 'high',
      conditions: [`role=${entityType}`, 'coverage_mode=synthesized_eu'],
      source_router: 'EU_Regulations_MCP:NIS2_ART_21',
      regulation_refs: ['NIS2_ART_21'],
      standard_refs: ['ISO_27001'],
      confidence: 'inferred',
      basis:
        'EU healthcare operators are often treated as essential or important entities for NIS2-aligned controls.',
      regulation_id: 'NIS2_ART_21',
      standard_id: 'ISO_27001',
      synthesized: true,
    });

    obligations.push({
      obligation_id: `synth_${countryCode.toLowerCase()}_member_state_law`,
      name: 'EU member-state healthcare law overlay',
      jurisdiction: countryCode,
      priority: 'high',
      conditions: [`role=${entityType}`, 'coverage_mode=synthesized_eu'],
      source_router: 'EU-law-mcp:member_state_healthcare_data',
      regulation_refs: [`${countryCode}_HEALTHCARE_DATA_LAW`],
      standard_refs: [],
      confidence: 'estimated',
      basis:
        'Member-state healthcare confidentiality, recordkeeping, and transfer constraints require local-law verification.',
      regulation_id: `${countryCode}_HEALTHCARE_DATA_LAW`,
      standard_id: null,
      synthesized: true,
    });

    if (domainFlags.has_medical_devices) {
      obligations.push({
        obligation_id: `synth_${countryCode.toLowerCase()}_mdr`,
        name: 'EU MDR cybersecurity and safety requirements',
        jurisdiction: countryCode,
        priority: 'critical',
        conditions: [`role=${entityType}`, 'coverage_mode=synthesized_eu'],
        source_router: 'EU_Regulations_MCP:MDR_ANNEX_I',
        regulation_refs: ['MDR_ANNEX_I'],
        standard_refs: ['IEC_62304', 'ISO_14971', 'IEC_80001_1'],
        confidence: 'inferred',
        basis:
          'Medical-device environments in EU jurisdictions typically require MDR Annex I-aligned cybersecurity controls.',
        regulation_id: 'MDR_ANNEX_I',
        standard_id: 'IEC_62304',
        synthesized: true,
      });
    }

    if (domainFlags.uses_ai_for_clinical_decisions) {
      obligations.push({
        obligation_id: `synth_${countryCode.toLowerCase()}_ai_act`,
        name: 'EU AI Act high-risk health-AI obligations',
        jurisdiction: countryCode,
        priority: 'high',
        conditions: [`role=${entityType}`, 'coverage_mode=synthesized_eu'],
        source_router: 'EU_Regulations_MCP:AI_ACT',
        regulation_refs: ['AI_ACT_ANNEX_III_HEALTH'],
        standard_refs: ['ISO_14971', 'IEC_62304'],
        confidence: 'inferred',
        basis:
          'Clinical AI use-cases in diagnosis or treatment support can trigger high-risk AI obligations in EU contexts.',
        regulation_id: 'AI_ACT_ANNEX_III_HEALTH',
        standard_id: 'ISO_14971',
        synthesized: true,
      });
    }
  }

  return obligations;
}

export function assessHealthcareApplicability(
  db: SqlDatabase,
  args: unknown,
): Record<string, unknown> | ToolError {
  const input = args as AssessHealthcareApplicabilityInput & {
    country?: string;
    role?: string;
    system_types?: string[];
    data_types?: string[];
    detail_level?: 'summary' | 'standard' | 'full';
    additional_context?: {
      has_medical_devices?: boolean;
      uses_ai_for_clinical_decisions?: boolean;
      jurisdictions?: string[];
      country_codes?: string[];
    };
  };

  const countryCodes = parseCountryCodes(input.country, input.additional_context?.country_codes);
  const detailLevel = input.detail_level ?? 'full';
  const countryJurisdiction = [...new Set(countryCodes.flatMap((countryCode) => countryToJurisdiction(countryCode)))];

  const derivedProfile = input.organization_profile ?? {
    jurisdictions:
      input.additional_context?.jurisdictions ??
      (countryJurisdiction.length > 0 ? countryJurisdiction : []),
    entity_type: (input.role ?? 'provider').toLowerCase(),
    data_categories: input.data_types ?? [],
    has_medical_devices: input.additional_context?.has_medical_devices ?? false,
    uses_ai_for_clinical_decisions: input.additional_context?.uses_ai_for_clinical_decisions ?? false,
  };

  const profile = derivedProfile;

  if (!profile || !Array.isArray(profile.jurisdictions) || !Array.isArray(profile.data_categories)) {
    return {
      error: 'organization_profile with jurisdictions and data_categories is required',
      hint: 'Provide entity_type and whether medical devices or clinical AI are in scope.',
    };
  }

  const inputSystemTypes = input.system_types ?? [];
  const inputDataTypes = input.data_types ?? profile.data_categories;
  const systemTypes = normalizeTokenSet(inputSystemTypes);
  const dataTypes = normalizeTokenSet(inputDataTypes);

  const jurisdictions = new Set(profile.jurisdictions.map((item) => item.toUpperCase()));
  const entityType = (input.role ?? profile.entity_type).toLowerCase();

  const rows = db
    .prepare(
      `SELECT profile_id, name, jurisdiction, entity_type, conditions, priority, source_router
       FROM obligation_profiles
       ORDER BY priority, profile_id`,
    )
    .all() as ObligationRow[];

  const matched = rows.filter((row) => {
    const rowJurisdiction = row.jurisdiction.toUpperCase();
    const jurisdictionMatch =
      rowJurisdiction === 'US_EU' ||
      jurisdictions.has(rowJurisdiction) ||
      (jurisdictions.has('US') && rowJurisdiction === 'US') ||
      (jurisdictions.has('EU') && rowJurisdiction === 'EU');
    const entityMatch = row.entity_type === entityType || row.entity_type === 'manufacturer';
    return jurisdictionMatch && entityMatch;
  });

  const criticalDataTags = new Set([
    'ephi',
    'part2_substance_use',
    'genetic_data',
    'special_category_health_data',
    'mental_health',
    'health_data',
  ]);

  const hasCriticalData = [...dataTypes].some((category) => criticalDataTags.has(category));
  const inferredMedicalDevices =
    Boolean(profile.has_medical_devices) ||
    Boolean(input.additional_context?.has_medical_devices) ||
    includesMedicalDeviceSystem(systemTypes);
  const inferredAi =
    Boolean(profile.uses_ai_for_clinical_decisions) ||
    Boolean(input.additional_context?.uses_ai_for_clinical_decisions);

  const domainFlags = {
    has_medical_devices: inferredMedicalDevices,
    uses_ai_for_clinical_decisions: inferredAi,
    high_sensitivity_data: hasCriticalData,
  };
  const normalizedJurisdictions = new Set(
    [...jurisdictions, ...countryCodes.map((code) => normalizeJurisdictionCode(code))],
  );

  const dynamicRoutes: string[] = [];
  if (domainFlags.has_medical_devices) {
    dynamicRoutes.push('EU_Regulations_MCP:MDR_IVDR', 'US_Regulations_MCP:FDA_524B');
  }
  if (domainFlags.uses_ai_for_clinical_decisions) {
    dynamicRoutes.push('EU_Regulations_MCP:AI_ACT', 'US-law-mcp:state_ai_healthcare_overlays');
  }
  if (hasCriticalData) {
    dynamicRoutes.push('Security_Controls_MCP:high_assurance_control_profile');
  }

  const baseObligations = matched.map((row) => ({
    obligation_id: row.profile_id,
    profile_id: row.profile_id,
    name: row.name,
    jurisdiction: row.jurisdiction,
    priority: row.priority,
    conditions: parseJsonArray(row.conditions),
    source_router: row.source_router,
    regulation_refs: refsFromRouter(row.source_router),
    standard_refs: [] as string[],
    confidence: 'inferred' as const,
    basis: 'Baseline domain profile match by jurisdiction and entity type.',
    regulation_id: refsFromRouter(row.source_router)[0] ?? null,
    standard_id: null,
  })) as ApplicabilityObligation[];

  let overlayObligations: ApplicabilityObligation[] = [];
  if (countryCodes.length > 0) {
    const placeholders = countryCodes.map(() => '?').join(', ');
    const overlays = db
      .prepare(
        `SELECT overlay_id, country_code, role, system_type, data_type, requires_ai,
                requires_medical_devices, obligation_name, priority, source_router,
                regulation_refs, standard_refs, basis, confidence
         FROM jurisdiction_overlays
         WHERE country_code IN (${placeholders})
         ORDER BY priority, overlay_id`,
      )
      .all(...countryCodes) as OverlayRow[];

    overlayObligations = overlays
      .filter((overlay) => {
        const roleMatch = overlay.role === 'any' || overlay.role.toLowerCase() === entityType;
        const systemMatch =
          overlay.system_type === 'any' || systemTypes.has(overlay.system_type.toLowerCase());
        const dataMatch = overlay.data_type === 'any' || dataTypes.has(overlay.data_type.toLowerCase());
        const aiMatch = overlay.requires_ai === 0 || domainFlags.uses_ai_for_clinical_decisions;
        const deviceMatch = overlay.requires_medical_devices === 0 || domainFlags.has_medical_devices;

        return roleMatch && systemMatch && dataMatch && aiMatch && deviceMatch;
      })
      .map((overlay): ApplicabilityObligation => {
        const regulationRefs = parseJsonArray(overlay.regulation_refs);
        const standardRefs = parseJsonArray(overlay.standard_refs);

        return {
          obligation_id: overlay.overlay_id,
          name: overlay.obligation_name,
          jurisdiction: overlay.country_code,
          priority: overlay.priority,
          conditions: [
            `role=${overlay.role}`,
            `system_type=${overlay.system_type}`,
            `data_type=${overlay.data_type}`,
          ],
          source_router: overlay.source_router,
          regulation_refs: regulationRefs,
          standard_refs: standardRefs,
          confidence: overlay.confidence,
          basis: overlay.basis,
          regulation_id: regulationRefs[0] ?? null,
          standard_id: standardRefs[0] ?? null,
          overlay: true,
        };
      });
  }

  const overlayCountries = new Set(overlayObligations.map((item) => item.jurisdiction));
  const synthesizedCountries: string[] = [];
  const supportedCountries: string[] = [];
  const unsupportedCountries: string[] = [];
  const synthesizedObligations: ApplicabilityObligation[] = [];

  for (const countryCode of countryCodes) {
    const family = jurisdictionFamily(countryCode);
    const supported = family === 'US' || family === 'EU';

    if (!supported) {
      unsupportedCountries.push(countryCode);
      continue;
    }

    supportedCountries.push(countryCode);

    if (!overlayCountries.has(countryCode)) {
      const synthesized = buildSynthesizedCountryObligations(countryCode, entityType, domainFlags);
      if (synthesized.length > 0) {
        synthesizedCountries.push(countryCode);
        synthesizedObligations.push(...synthesized);
      }
    }
  }

  const obligations = Array.from(
    new Map(
      [...baseObligations, ...overlayObligations, ...synthesizedObligations].map((item) => [
        `${String(item.jurisdiction)}|${String(item.name)}|${String(item.source_router)}`,
        item,
      ]),
    ).values(),
  );

  const baselinePriority =
    obligations.some((item) => item.priority === 'critical') || hasCriticalData
      ? 'critical'
      : obligations.some((item) => item.priority === 'high')
        ? 'high'
        : 'moderate';

  const outOfScope: string[] = [];
  for (const countryCode of unsupportedCountries) {
    outOfScope.push(`Country code ${countryCode} is outside current US/EU support scope.`);
  }

  const conflictResolution = resolveApplicabilityConflicts(obligations);
  const obligationById = new Map(obligations.map((item) => [item.obligation_id, item]));
  const strictestSelected = conflictResolution.strictest_obligations
    .map((item) => obligationById.get(item.obligation_id))
    .filter((item): item is ApplicabilityObligation => Boolean(item));

  const hasEstimatedStrictest = strictestSelected.some((item) => item.confidence === 'estimated');
  const contractingObligations = buildContractingObligations(
    normalizedJurisdictions,
    dataTypes,
    domainFlags,
  );
  const hasEstimatedContracting = contractingObligations.some(
    (obligation) => obligation.applies && obligation.confidence === 'estimated',
  );
  const requiresAuthoritativeValidation =
    hasEstimatedStrictest ||
    hasEstimatedContracting ||
    synthesizedCountries.length > 0 ||
    unsupportedCountries.length > 0;

  const fullResponse = {
    organization_profile: profile,
    input_profile: {
      country: input.country ?? null,
      country_codes: countryCodes,
      role: input.role ?? null,
      system_types: inputSystemTypes,
      data_types: inputDataTypes,
      detail_level: detailLevel,
    },
    scope_status: obligations.length > 0 ? 'in_scope' : outOfScope.length > 0 ? 'out_of_scope' : 'not_indexed',
    domain_flags: domainFlags,
    obligations,
    baseline_priority: baselinePriority,
    router_calls_required: [...new Set([...obligations.map((item) => String(item.source_router)), ...dynamicRoutes])],
    overlay_summary: {
      country_codes: countryCodes,
      overlay_match_count: overlayObligations.length,
      synthesized_match_count: synthesizedObligations.length,
      synthesized_country_codes: synthesizedCountries,
      supported_country_codes: supportedCountries,
      unsupported_country_codes: unsupportedCountries,
      out_of_scope: outOfScope,
    },
    contracting_obligations: contractingObligations,
    conflict_resolution: conflictResolution,
    decision_quality: {
      confidence_floor: hasEstimatedStrictest || hasEstimatedContracting ? 'estimated' : 'inferred',
      requires_authoritative_validation: requiresAuthoritativeValidation,
      abstain_from_definitive_legal_advice: requiresAuthoritativeValidation,
      rationale: requiresAuthoritativeValidation
        ? 'One or more selected obligations are synthesized/estimated or jurisdiction support is partial; validate with upstream authoritative MCP sources.'
        : 'Selected obligations are covered by explicit overlays and inferred/authoritative domain mappings.',
    },
    next_actions: [
      'Call resolve_authoritative_context to fetch live authoritative context from configured upstream MCP endpoints.',
      'Call compare_jurisdictions for high-risk topics (breach, cross-border transfer, AI in diagnostics).',
      'Validate BAA/DPA/SCC contract chain obligations with law/regulation MCPs before final legal position.',
      'Call build_healthcare_baseline to materialize control priorities.',
    ],
  };

  if (detailLevel === 'summary') {
    return {
      organization_profile: profile,
      input_profile: fullResponse.input_profile,
      scope_status: fullResponse.scope_status,
      baseline_priority: fullResponse.baseline_priority,
      obligation_count: obligations.length,
      top_obligations: obligations.slice(0, 5).map((obligation) => ({
        obligation_id: obligation.obligation_id,
        name: obligation.name,
        jurisdiction: obligation.jurisdiction,
        priority: obligation.priority,
        source_router: obligation.source_router,
      })),
      router_calls_required: fullResponse.router_calls_required,
      overlay_summary: fullResponse.overlay_summary,
      decision_quality: fullResponse.decision_quality,
      next_actions: fullResponse.next_actions,
    };
  }

  if (detailLevel === 'standard') {
    return {
      ...fullResponse,
      conflict_resolution: fullResponse.conflict_resolution,
      contracting_obligations: fullResponse.contracting_obligations,
      obligations: fullResponse.obligations.map((obligation) => ({
        obligation_id: obligation.obligation_id,
        name: obligation.name,
        jurisdiction: obligation.jurisdiction,
        priority: obligation.priority,
        source_router: obligation.source_router,
        regulation_refs: obligation.regulation_refs,
        standard_refs: obligation.standard_refs,
        confidence: obligation.confidence,
        basis: obligation.basis,
        overlay: obligation.overlay ?? false,
        synthesized: obligation.synthesized ?? false,
      })),
    };
  }

  return fullResponse;
}
