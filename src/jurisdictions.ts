export const EU_COUNTRY_CODES = new Set([
  'AT',
  'BE',
  'BG',
  'HR',
  'CY',
  'CZ',
  'DK',
  'EE',
  'FI',
  'FR',
  'DE',
  'GR',
  'HU',
  'IE',
  'IT',
  'LV',
  'LT',
  'LU',
  'MT',
  'NL',
  'PL',
  'PT',
  'RO',
  'SK',
  'SI',
  'ES',
  'SE',
]);

export const US_STATE_CODES = new Set([
  'AL',
  'AK',
  'AZ',
  'AR',
  'CA',
  'CO',
  'CT',
  'DE',
  'FL',
  'GA',
  'HI',
  'ID',
  'IL',
  'IN',
  'IA',
  'KS',
  'KY',
  'LA',
  'ME',
  'MD',
  'MA',
  'MI',
  'MN',
  'MS',
  'MO',
  'MT',
  'NE',
  'NV',
  'NH',
  'NJ',
  'NM',
  'NY',
  'NC',
  'ND',
  'OH',
  'OK',
  'OR',
  'PA',
  'RI',
  'SC',
  'SD',
  'TN',
  'TX',
  'UT',
  'VT',
  'VA',
  'WA',
  'WV',
  'WI',
  'WY',
  'DC',
]);

export type JurisdictionFamily = 'US' | 'EU' | 'OTHER';

export function normalizeJurisdictionCode(input: string): string {
  return input.trim().toUpperCase().replace('_', '-');
}

export function isUsJurisdiction(code: string): boolean {
  if (code === 'US' || code === 'US_EU') {
    return true;
  }
  if (!code.startsWith('US-')) {
    return false;
  }
  const state = code.slice(3);
  return US_STATE_CODES.has(state);
}

export function isEuJurisdiction(code: string): boolean {
  if (code === 'EU' || code === 'US_EU') {
    return true;
  }
  return EU_COUNTRY_CODES.has(code);
}

export function jurisdictionFamily(code: string): JurisdictionFamily {
  if (isUsJurisdiction(code)) {
    return 'US';
  }
  if (isEuJurisdiction(code)) {
    return 'EU';
  }
  return 'OTHER';
}

export function countryCodeFromUsJurisdiction(code: string): string | null {
  if (code === 'US') {
    return null;
  }
  if (code.startsWith('US-') && code.length === 5) {
    return code.slice(3);
  }
  return null;
}
