// ═══════════════════════════════════════════════════════════════
// Checks if env var name looks sensitive based on patterns
// Patterns: KEY, SECRET, TOKEN, PASSWORD, API, PRIVATE, etc.
// ═══════════════════════════════════════════════════════════════
export function isSensitiveKey(key: string, patterns: RegExp[]): boolean {
  return patterns.some(pattern => pattern.test(key))
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
    .filter(({ value }) => value.length >= 3) // Skip very short values (avoid false positives)
    .sort((a, b) => b.value.length - a.value.length)
  
  // Pre-compile escape function for regex special chars
  const escapeRegex = (str: string) => 
    str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  
  // Pre-build regex patterns for each value
  const patterns = sortedVars.map(({ key, value }) => ({
    key,
    regex: new RegExp(escapeRegex(value), "g"),
  }))
  
  // Return redactor function
  return (text: string): string => {
    let result = text
    
    for (const { key, regex } of patterns) {
      // Reset regex lastIndex for global flag
      regex.lastIndex = 0
      result = result.replace(regex, `[ENV:${key}]`)
    }
    
    return result
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
