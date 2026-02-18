type Priority = 'critical' | 'high' | 'moderate';
type Confidence = 'authoritative' | 'inferred' | 'estimated';

export type ApplicabilityConflictObligation = {
  obligation_id: string;
  jurisdiction: string;
  priority: Priority;
  source_router: string;
  regulation_refs: string[];
  standard_refs: string[];
  confidence: Confidence;
  overlay?: boolean;
  synthesized?: boolean;
};

type ConflictFamily =
  | 'data_privacy'
  | 'cybersecurity_program'
  | 'device_cybersecurity'
  | 'clinical_ai'
  | 'local_legal_overlay'
  | 'general';

type ConflictCandidate = {
  obligation_id: string;
  jurisdiction: string;
  priority: Priority;
  confidence: Confidence;
  source_router: string;
  regulation_refs: string[];
  strictness_score: number;
  selection_reason: string;
};

type ConflictDecision = {
  family: ConflictFamily;
  conflict_type: 'overlapping_obligations';
  selected_obligation_id: string;
  selected_jurisdiction: string;
  selected_priority: Priority;
  selected_source_router: string;
  selected_regulation_refs: string[];
  selected_strictness_score: number;
  contenders: ConflictCandidate[];
  resolution_rule: string;
  rationale: string;
};

type ConflictSummary = {
  total_obligations: number;
  families_evaluated: number;
  conflicts_detected: number;
  resolved_by_policy: number;
};

type ConflictResolutionOutput = {
  policy: {
    name: string;
    strictness_order: string[];
    tie_breakers: string[];
  };
  strictest_obligations: Array<{
    family: ConflictFamily;
    obligation_id: string;
    jurisdiction: string;
    priority: Priority;
    source_router: string;
    strictness_score: number;
  }>;
  conflicts: ConflictDecision[];
  summary: ConflictSummary;
};

function priorityScore(priority: Priority): number {
  switch (priority) {
    case 'critical':
      return 3;
    case 'high':
      return 2;
    case 'moderate':
      return 1;
    default:
      return 0;
  }
}

function confidenceScore(confidence: Confidence): number {
  switch (confidence) {
    case 'authoritative':
      return 3;
    case 'inferred':
      return 2;
    case 'estimated':
      return 1;
    default:
      return 0;
  }
}

function specificityScore(item: ApplicabilityConflictObligation): number {
  if (item.overlay && !item.synthesized) {
    return 3;
  }
  if (item.synthesized) {
    return 2;
  }
  return 1;
}

function jurisdictionSpecificityScore(jurisdiction: string): number {
  return jurisdiction.includes('-') ? 2 : 1;
}

function strictnessScore(item: ApplicabilityConflictObligation): number {
  const refDensity = Math.min(5, (item.regulation_refs?.length ?? 0) + (item.standard_refs?.length ?? 0));
  return (
    priorityScore(item.priority) * 10000 +
    confidenceScore(item.confidence) * 1000 +
    specificityScore(item) * 100 +
    jurisdictionSpecificityScore(item.jurisdiction) * 10 +
    refDensity
  );
}

function classifyFamily(item: ApplicabilityConflictObligation): ConflictFamily {
  const corpus = [
    item.source_router,
    ...item.regulation_refs,
    ...item.standard_refs,
  ]
    .join(' ')
    .toUpperCase();

  if (
    corpus.includes('GDPR') ||
    corpus.includes('HIPAA') ||
    corpus.includes('CMIA') ||
    corpus.includes('BDSG') ||
    corpus.includes('PART 2') ||
    corpus.includes('PART_2')
  ) {
    return 'data_privacy';
  }

  if (corpus.includes('MDR') || corpus.includes('IVDR') || corpus.includes('FDA_524B')) {
    return 'device_cybersecurity';
  }

  if (corpus.includes('AI_ACT') || corpus.includes('FDA_AI')) {
    return 'clinical_ai';
  }

  if (corpus.includes('NIS2') || corpus.includes('ISO_27001') || corpus.includes('NIST_SP_800_66')) {
    return 'cybersecurity_program';
  }

  if (corpus.includes('LAW-MCP') || corpus.includes('_LAW') || corpus.includes('STATE_HEALTH_PRIVACY')) {
    return 'local_legal_overlay';
  }

  return 'general';
}

function byStrictnessDescending(
  a: ApplicabilityConflictObligation,
  b: ApplicabilityConflictObligation,
): number {
  const scoreDelta = strictnessScore(b) - strictnessScore(a);
  if (scoreDelta !== 0) {
    return scoreDelta;
  }

  const refsDelta = (b.regulation_refs.length + b.standard_refs.length) -
    (a.regulation_refs.length + a.standard_refs.length);
  if (refsDelta !== 0) {
    return refsDelta;
  }

  return a.obligation_id.localeCompare(b.obligation_id);
}

function conflictDetected(items: ApplicabilityConflictObligation[]): boolean {
  if (items.length <= 1) {
    return false;
  }

  const refSignatures = new Set(
    items.map((item) =>
      [...item.regulation_refs, ...item.standard_refs].sort().join('|'),
    ),
  );
  const prioritySet = new Set(items.map((item) => item.priority));
  const routeSet = new Set(items.map((item) => item.source_router));

  return refSignatures.size > 1 || prioritySet.size > 1 || routeSet.size > 1;
}

export function resolveApplicabilityConflicts(
  obligations: ApplicabilityConflictObligation[],
): ConflictResolutionOutput {
  const groups = new Map<ConflictFamily, ApplicabilityConflictObligation[]>();

  for (const obligation of obligations) {
    const family = classifyFamily(obligation);
    const current = groups.get(family) ?? [];
    current.push(obligation);
    groups.set(family, current);
  }

  const strictestObligations: ConflictResolutionOutput['strictest_obligations'] = [];
  const conflicts: ConflictDecision[] = [];

  for (const [family, items] of groups.entries()) {
    const ranked = [...items].sort(byStrictnessDescending);
    const selected = ranked[0];

    strictestObligations.push({
      family,
      obligation_id: selected.obligation_id,
      jurisdiction: selected.jurisdiction,
      priority: selected.priority,
      source_router: selected.source_router,
      strictness_score: strictnessScore(selected),
    });

    if (!conflictDetected(items)) {
      continue;
    }

    const contenders: ConflictCandidate[] = ranked.map((item) => ({
      obligation_id: item.obligation_id,
      jurisdiction: item.jurisdiction,
      priority: item.priority,
      confidence: item.confidence,
      source_router: item.source_router,
      regulation_refs: item.regulation_refs,
      strictness_score: strictnessScore(item),
      selection_reason:
        item.obligation_id === selected.obligation_id
          ? 'selected_by_strictness_policy'
          : 'superseded_by_stricter_obligation',
    }));

    conflicts.push({
      family,
      conflict_type: 'overlapping_obligations',
      selected_obligation_id: selected.obligation_id,
      selected_jurisdiction: selected.jurisdiction,
      selected_priority: selected.priority,
      selected_source_router: selected.source_router,
      selected_regulation_refs: selected.regulation_refs,
      selected_strictness_score: strictnessScore(selected),
      contenders,
      resolution_rule:
        'strictest_wins(priority > confidence > specificity > jurisdiction_specificity > citation_density > obligation_id)',
      rationale:
        `Selected ${selected.obligation_id} as strictest obligation in ${family} based on deterministic ranking policy.`,
    });
  }

  strictestObligations.sort((a, b) => b.strictness_score - a.strictness_score);

  return {
    policy: {
      name: 'strictest_wins',
      strictness_order: [
        'priority',
        'confidence',
        'obligation_specificity',
        'jurisdiction_specificity',
        'citation_density',
      ],
      tie_breakers: ['obligation_id_lexicographic'],
    },
    strictest_obligations: strictestObligations,
    conflicts,
    summary: {
      total_obligations: obligations.length,
      families_evaluated: groups.size,
      conflicts_detected: conflicts.length,
      resolved_by_policy: conflicts.length,
    },
  };
}
