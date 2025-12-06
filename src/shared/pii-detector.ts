export type PiiType =
  | 'CREDIT_CARD'
  | 'SSN'
  | 'EMAIL'
  | 'PHONE'
  | 'API_KEY'
  | 'AWS_KEY'
  | 'PRIVATE_KEY'
  | 'IP_ADDRESS'
  | 'HIPAA_MRN'
  | 'HIPAA_ACCOUNT'
  | 'HIPAA_DOB'
  | 'PCI_CVV'
  | 'PCI_PAN'
  | 'PCI_TRACK'
  | 'PCI_EXPIRY'
  | 'GDPR_PASSPORT'
  | 'GDPR_NIN'
  | 'GDPR_IBAN'
  | 'CUSTOM'; // For user-defined patterns

export type DetectionResult = {
  type: PiiType | string;
  value: string;
  start?: number;
  end?: number;
  confidence?: number;
  patternName?: string;
};

export type CustomPattern = {
  id: string;
  name: string;
  pattern: string;
  pattern_type: string;
  description?: string;
  is_active: boolean | number | string;
};

// Built-in patterns
const BUILT_IN_PATTERNS: Array<{
  type: PiiType;
  regex: RegExp;
  validate?: (value: string) => boolean;
}> = [
  {
    type: 'CREDIT_CARD',
    regex:
      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    validate: luhnCheck,
  },
  {
    type: 'SSN',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: 'EMAIL',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  },
  {
    type: 'PHONE',
    regex: /\b(\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
  },
  {
    type: 'API_KEY',
    regex: /(?:api[_-]?key|apikey)["\s:=]+["']?([a-zA-Z0-9_\-]{20,})["']?/gi,
  },
  {
    type: 'AWS_KEY',
    regex: /AKIA[0-9A-Z]{16}/g,
  },
  {
    type: 'PRIVATE_KEY',
    regex:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+\/=\s\n\r]+-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gs,
  },
  {
    type: 'IP_ADDRESS',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  },
  // HIPAA patterns
  {
    type: 'HIPAA_MRN',
    regex: /\bMRN[-\s]?\d{6,12}\b/gi,
  },
  {
    type: 'HIPAA_ACCOUNT',
    regex: /\bAccount[-\s]?(?:Number|#)?[-\s]?\d{6,12}\b/gi,
  },
  {
    type: 'HIPAA_DOB',
    regex: /\b(?:DOB|Date of Birth)[-\s:]?\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/gi,
  },
  // PCI-DSS patterns
  {
    type: 'PCI_CVV',
    regex:
      /\b(?:CVV|CVC|Card Verification)[-\s]?(?:Value|Code)?[-\s]?\d{3,4}\b/gi,
  },
  {
    type: 'PCI_PAN',
    regex: /\b(?:PAN|Primary Account Number)[-\s]?\d{13,19}\b/gi,
  },
  {
    type: 'PCI_TRACK',
    regex: /\b%?[A-Z]\d{13,19}=[\d?]{4,}\b/g,
  },
  {
    type: 'PCI_EXPIRY',
    regex: /\b(?:Exp|Expiry|Expiration)[-\s:]?\d{1,2}[/-]\d{2,4}\b/gi,
  },
  // GDPR patterns
  {
    type: 'GDPR_PASSPORT',
    regex: /\b(?:Passport|Passport Number|Passport #)[-\s:]?[A-Z0-9]{6,9}\b/gi,
  },
  {
    type: 'GDPR_NIN',
    regex: /\b(?:NI|NINO|National Insurance)[-\s]?[A-Z]{2}\d{6}[A-Z]\b/gi,
  },
  {
    type: 'GDPR_IBAN',
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/g,
  },
];

// Store custom patterns (fetched from API)
let customPatterns: CustomPattern[] = [];

// Luhn algorithm for credit card validation
function luhnCheck(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let isEven = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i]);

    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

// Set custom patterns (called after fetching from API)
export function setCustomPatterns(patterns: CustomPattern[]) {
  customPatterns = patterns.filter(p => {
    // Handle various types that might come from API (boolean, number, string)
    const isActive = p.is_active;
    if (typeof isActive === 'boolean') {
      return isActive;
    }
    if (typeof isActive === 'number') {
      return isActive === 1;
    }
    if (typeof isActive === 'string') {
      return isActive === '1' || isActive.toLowerCase() === 'true';
    }
    return false;
  });

  // Test each pattern
  customPatterns.forEach(p => {
    try {
      const regex = new RegExp(p.pattern, 'gi');
      const testResult = regex.test('EMP-123456');
    } catch (e) {
      console.error(`❌ Pattern "${p.name}" regex error:`, e);
    }
  });
}
// Main detection function
export function detectPii(text: string): DetectionResult[] {
  if (!text || text.length === 0) return [];

  const results: DetectionResult[] = [];

  // Check built-in patterns
  for (const pattern of BUILT_IN_PATTERNS) {
    const matches = text.matchAll(pattern.regex);

    for (const match of matches) {
      const value = match[0];

      // Skip if validation function exists and fails
      if (pattern.validate && !pattern.validate(value)) {
        continue;
      }

      results.push({
        type: pattern.type,
        value,
        start: match.index,
        end: match.index ? match.index + value.length : undefined,
      });
    }
  }

  // Check custom patterns
  for (const customPattern of customPatterns) {
    try {
      const regex = new RegExp(customPattern.pattern, 'gi');
      const matches = text.matchAll(regex);

      for (const match of matches) {
        const value = match[0];

        results.push({
          type: customPattern.pattern_type,
          value,
          start: match.index,
          end: match.index ? match.index + value.length : undefined,
          confidence: 0.9,
          patternName: customPattern.name,
        });
      }
    } catch (error) {
      console.error(`Invalid custom pattern: ${customPattern.name}`, error);
    }
  }
  // Remove duplicates (same value and type)
  const uniqueResults = results.filter(
    (result, index, self) =>
      index ===
      self.findIndex(r => r.type === result.type && r.value === result.value)
  );

  return uniqueResults;
}
