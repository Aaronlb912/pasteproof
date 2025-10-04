// src/shared/pii-detector.ts

export enum PiiType {
  CreditCard = 'Credit Card',
  SSN = 'Social Security Number',
  PhoneNumber = 'Phone Number',
  Email = 'Email Address',
  APIKey = 'API Key',
}

export interface DetectionResult {
  type: PiiType;
  value: string;
  startIndex: number;
}

function luhnCheck(numStr: string): boolean {
  if (/[^0-9-\s]+/.test(numStr)) return false;

  let sum = 0;
  let shouldDouble = false;
  // Iterate from right to left
  for (let i = numStr.length - 1; i >= 0; i--) {
    const char = numStr.charAt(i);
    if (char === ' ' || char === '-') continue;

    let digit = parseInt(char, 10);

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

export function detectPii(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];

  // Credit Card Detection (with Luhn validation)
  const ccRegex = /(?:\d[ -]*){13,19}/g; 
  for (const match of text.matchAll(ccRegex)) {
    const cleaned = match[0].replace(/[\s-]/g, '');
    
    if (cleaned.length >= 13 && cleaned.length <= 16 && luhnCheck(cleaned)) {
      results.push({
        type: PiiType.CreditCard,
        value: match[0],
        startIndex: match.index!,
      });
    }
  }

  // SSN Detection (with basic validation)
  const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
  for (const match of text.matchAll(ssnRegex)) {
     // Basic validation: Not all zeros, not 666, etc.
    if (!match[0].startsWith('000') && !match[0].startsWith('666')) {
        results.push({
            type: PiiType.SSN,
            value: match[0],
            startIndex: match.index!,
        });
    }
  }

  // Phone Number Detection (US/CA)
  const phoneRegex = /\b(?:\+?1[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}\b/g;
  for (const match of text.matchAll(phoneRegex)) {
    results.push({
      type: PiiType.PhoneNumber,
      value: match[0],
      startIndex: match.index!,
    });
  }

  // Email Detection
  const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
  for (const match of text.matchAll(emailRegex)) {
    results.push({
      type: PiiType.Email,
      value: match[0],
      startIndex: match.index!,
    });
  }

  // API Key Detection (common prefixes)
  const apiKeyRegex = /\b(sk|pk|rk)_(test|live)_[a-zA-Z0-9]{24,}\b/g;
   for (const match of text.matchAll(apiKeyRegex)) {
    results.push({
      type: PiiType.APIKey,
      value: match[0],
      startIndex: match.index!,
    });
  }

  return results;
}

