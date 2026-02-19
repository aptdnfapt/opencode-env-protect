// ═══════════════════════════════════════════════════════════════
// Checks if env var name looks sensitive based on patterns
// Patterns: KEY, SECRET, TOKEN, PASSWORD, API, PRIVATE, etc.
// ═══════════════════════════════════════════════════════════════
export function isSensitiveKey(key: string, patterns: RegExp[]): boolean {
  return patterns.some(pattern => pattern.test(key))
}

// ═══════════════════════════════════════════════════════════════
// VALUES TO NEVER REDACT - common non-secret values
// ═══════════════════════════════════════════════════════════════
const VALUE_BLOCKLIST = new Set([
  // Booleans
  "true", "false", "yes", "no", "on", "off", "1", "0",
  // Common hosts
  "localhost", "127.0.0.1", "0.0.0.0", "::1",
  // Null-ish
  "null", "undefined", "none", "empty", "nil",
  // Common defaults
  "default", "test", "dev", "prod", "staging", "development", "production",
  // Common words that appear in configs
  "id", "name", "user", "admin", "root", "guest",
  // Common default DB passwords - would cause false positives everywhere
  "postgres", "postgresql", "mysql", "mariadb", "mongodb", "redis",
  "password", "pass", "secret", "changeme", "letmein", "123456", "12345678",
  "qwerty", "abc123", "password123", "admin123", "root123",
])

// ═══════════════════════════════════════════════════════════════
// Extract password from database connection strings
// Handles: postgres, mysql, mongodb, redis, amqp, mssql, mariadb, etc.
// Format: protocol://user:PASSWORD@host:port/db
// ═══════════════════════════════════════════════════════════════
const DB_URL_REGEX = /^(postgres|postgresql|mysql|mongodb(\+srv)?|redis|rediss|amqp|amqps|mssql|mariadb|cockroachdb|jdbc:[a-z]+):\/\/([^:]*):([^@]+)@/i

export function extractDbPassword(value: string): string | null {
  const match = value.match(DB_URL_REGEX)
  if (match && match[4]) {
    // match[4] is the password part (after user: and before @)
    const password = match[4]
    // Skip if password is a placeholder or too short
    if (password.length >= 4 && !VALUE_BLOCKLIST.has(password.toLowerCase())) {
      return password
    }
  }
  return null
}

// ═══════════════════════════════════════════════════════════════
// Known secret prefixes - if value starts with these, likely a secret
// ═══════════════════════════════════════════════════════════════
const SECRET_PREFIXES = [
  "sk-",      // OpenAI, Stripe
  "sk_",      // Stripe
  "pk_",      // Stripe public (still sensitive)
  "ghp_",     // GitHub personal token
  "gho_",     // GitHub OAuth
  "ghu_",     // GitHub user-to-server
  "ghs_",     // GitHub server-to-server
  "github_pat_", // GitHub PAT
  "xoxb-",    // Slack bot
  "xoxp-",    // Slack user
  "xoxa-",    // Slack app
  "xoxr-",    // Slack refresh
  "AKIA",     // AWS access key
  "eyJ",      // JWT (base64 encoded JSON)
  "Bearer ",  // Auth header value
  "Basic ",   // Basic auth
  "npm_",     // npm token
  "pypi-",    // PyPI token
  "glpat-",   // GitLab PAT
  "gloas-",   // GitLab OAuth
]

// ═══════════════════════════════════════════════════════════════
// Determines if a value should be redacted based on heuristics
// Returns false for common non-secret values
// ═══════════════════════════════════════════════════════════════
export function shouldRedactValue(value: string): boolean {
  const trimmed = value.trim()
  const lower = trimmed.toLowerCase()
  
  // Too short - skip
  if (trimmed.length < 4) return false
  
  // In blocklist - skip
  if (VALUE_BLOCKLIST.has(lower)) return false
  
  // Paths - skip (starts with / or ~ or C:\ etc)
  if (/^[\/~]/.test(trimmed) || /^[A-Za-z]:[\\\/]/.test(trimmed)) return false
  
  // URLs without auth - skip
  if (/^https?:\/\/[^@]*$/i.test(trimmed)) return false
  
  // Pure numbers < 6 digits - skip (ports, timeouts, etc)
  if (/^\d+$/.test(trimmed) && trimmed.length < 6) return false
  
  // Known secret prefix - ALWAYS redact
  if (SECRET_PREFIXES.some(prefix => trimmed.startsWith(prefix))) return true
  
  // Long value (>=20 chars) - likely a secret
  if (trimmed.length >= 20) return true
  
  // Medium length (>=12) with mixed chars (letter + digit) - likely secret
  if (trimmed.length >= 12) {
    const hasLetter = /[a-zA-Z]/.test(trimmed)
    const hasDigit = /\d/.test(trimmed)
    if (hasLetter && hasDigit) return true
  }
  
  // Has special chars common in secrets (but not paths/URLs)
  if (trimmed.length >= 8 && /[+\/=_-]/.test(trimmed)) {
    const hasLetter = /[a-zA-Z]/.test(trimmed)
    const hasDigit = /\d/.test(trimmed)
    if (hasLetter && hasDigit) return true
  }
  
  // Default: don't redact short simple values
  return trimmed.length >= 16
}

// ═══════════════════════════════════════════════════════════════
// Creates a redactor function that replaces sensitive values
// with [ENV:VAR_NAME] tags
// 
// Uses partial matching - if value "abc123" appears anywhere
// in text like "prefix_abc123_suffix", it gets redacted to
// "prefix_[ENV:API_KEY]_suffix"
// 
// Sorts by value length (longest first) to handle overlapping
// values correctly (e.g., if KEY1=abc and KEY2=abcdef)
// ═══════════════════════════════════════════════════════════════
export function createRedactor(sensitiveVars: Map<string, string>): (text: string) => string {
  // Build sorted list of [value, varName] pairs
  // Sort by value length descending - replace longer values first
  // This prevents partial replacements of longer values
  const sortedVars = Array.from(sensitiveVars.entries())
    .map(([key, value]) => ({ key, value }))
    .filter(({ value }) => shouldRedactValue(value)) // Use new heuristics
    .sort((a, b) => b.value.length - a.value.length)
  
  // Pre-compile escape function for regex special chars
  const escapeRegex = (str: string) => 
    str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  
  // Pre-build regex patterns for each value
  // Use word boundary for short values (<10 chars) to avoid partial matches
  const patterns = sortedVars.map(({ key, value }) => ({
    key,
    regex: value.length < 10 
      ? new RegExp(`\\b${escapeRegex(value)}\\b`, "g")  // Word boundary for short
      : new RegExp(escapeRegex(value), "g"),            // Substring for long
  }))
  
  // Return redactor function
  return (text: string): string => {
    let result = text
    
    for (const { key, regex } of patterns) {
      // Reset regex lastIndex for global flag
      regex.lastIndex = 0
      result = result.replace(regex, `[ENV:${key} was redacted]`)
    }
    
    return result
  }
}

// ═══════════════════════════════════════════════════════════════
// Creates a redactor that also tracks which vars were redacted
// Returns: { result: string, redactedVars: string[] }
// ═══════════════════════════════════════════════════════════════
export function createRedactorWithTracking(sensitiveVars: Map<string, string>): (text: string) => { result: string, redactedVars: string[] } {
  const sortedVars = Array.from(sensitiveVars.entries())
    .map(([key, value]) => ({ key, value }))
    .filter(({ value }) => shouldRedactValue(value))  // Use new heuristics
    .sort((a, b) => b.value.length - a.value.length)
  
  const escapeRegex = (str: string) => 
    str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  
  // Use word boundary for short values (<10 chars) to avoid partial matches
  const patterns = sortedVars.map(({ key, value }) => ({
    key,
    regex: value.length < 10 
      ? new RegExp(`\\b${escapeRegex(value)}\\b`, "g")  // Word boundary for short
      : new RegExp(escapeRegex(value), "g"),            // Substring for long
  }))
  
  return (text: string) => {
    let result = text
    const redactedVars: string[] = []
    
    for (const { key, regex } of patterns) {
      regex.lastIndex = 0
      if (regex.test(result)) {
        redactedVars.push(key)
        regex.lastIndex = 0
        result = result.replace(regex, `[ENV:${key} was redacted]`)
      }
    }
    
    return { result, redactedVars }
  }
}

// ═══════════════════════════════════════════════════════════════
// Alternative: Exact match redactor (not used by default)
// Only replaces if entire token equals the value
// Less secure but fewer false positives
// ═══════════════════════════════════════════════════════════════
export function createExactRedactor(sensitiveVars: Map<string, string>): (text: string) => string {
  const valueToKey = new Map<string, string>()
  for (const [key, value] of sensitiveVars) {
    if (value.length >= 3) {
      valueToKey.set(value, key)
    }
  }
  
  return (text: string): string => {
    // Split on whitespace and common delimiters
    const tokens = text.split(/(\s+|[,;:'"=\[\]{}()|<>])/g)
    
    return tokens.map(token => {
      const varName = valueToKey.get(token)
      return varName ? `[ENV:${varName}]` : token
    }).join("")
  }
}
