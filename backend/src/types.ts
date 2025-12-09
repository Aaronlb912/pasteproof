export interface ENV {
  API_KEY: string;
  AI: any; // Cloudflare AI binding
  WHITELIST_STORE: KVNamespace;
  PATTERNS_STORE: KVNamespace;
  DETECTIONS_STORE: KVNamespace;
  LOGS_STORE: KVNamespace;
}

export interface WhitelistEntry {
  id: string;
  domain: string;
  created_at: string;
}

export interface CustomPattern {
  id: string;
  name: string;
  pattern: string;
  pattern_type: string;
  description?: string;
  created_at: string;
}

export interface Detection {
  id: string;
  type: string;
  domain: string;
  action: string;
  metadata?: Record<string, any>;
  timestamp: string;
}

export interface AuditLog {
  id: string;
  event_type: string;
  domain: string;
  pii_type: string;
  was_anonymized: boolean;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface PIIDetection {
  type: string;
  value: string;
  confidence: number;
  reason?: string;
}

