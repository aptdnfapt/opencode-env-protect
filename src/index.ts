import type { Plugin, Hooks, PluginInput } from "@opencode-ai/plugin"
import { scanEnvFiles, parseEnvFile } from "./scanner"
import { isSensitiveKey, createRedactorWithTracking, shouldRedactValue, extractDbPassword } from "./redactor"
import { appendFileSync, existsSync } from "fs"
import { join } from "path"

// Store sensitive vars: { varName: actualValue } - these get REDACTED
const sensitiveVars: Map<string, string> = new Map()

// Store client for sending TUI messages
let _client: PluginInput["client"] | null = null

// Store ALL var names from .env files - these get LISTED in system prompt
const allEnvVarNames: Set<string> = new Set()

// ═══════════════════════════════════════════════════════════════
// DEBUG LOGGING - writes to ~/.opencode-env-protect.log
// Set OPENCODE_ENV_PROTECT_DEBUG=1 to enable
// ═══════════════════════════════════════════════════════════════
const DEBUG = process.env.OPENCODE_ENV_PROTECT_DEBUG === "1"
const LOG_FILE = join(process.env.HOME || "/tmp", ".opencode-env-protect.log")

function log(msg: string, data?: any) {
  if (!DEBUG) return
  const timestamp = new Date().toISOString()
  const line = data 
    ? `[${timestamp}] ${msg}: ${JSON.stringify(data, null, 2)}\n`
    : `[${timestamp}] ${msg}\n`
  try {
    appendFileSync(LOG_FILE, line)
  } catch {}
}

// Patterns that indicate sensitive env var names
const SENSITIVE_PATTERNS = [
  /KEY/i,
  /SECRET/i,
  /TOKEN/i,
  /PASSWORD/i,
  /PASSWD/i,
  /PRIVATE/i,
  /CREDENTIAL/i,
  /AUTH/i,
  /CERT/i,
  // Note: /API/i removed - too broad, catches API_URL which isn't sensitive
  // API_KEY, API_SECRET, API_TOKEN already caught by other patterns
]

// Env vars to NEVER redact (false positives)
const EXCLUDED_VARS = new Set([
  "PWD",      // current working directory
  "OLDPWD",   // previous directory
  "PATH",     // system path
  "HOME",     // home directory
  "USER",     // username
  "SHELL",    // shell path
  "TERM",     // terminal type
  "LANG",     // language
  "EDITOR",   // editor
  "PAGER",    // pager
])

export const EnvProtectPlugin: Plugin = async (ctx) => {
  const { directory } = ctx
  
  // ═══════════════════════════════════════════════════════════════
  // GATE: Only activate if this is a git repository
  // Prevents plugin from breaking stuff in random directories
  // ═══════════════════════════════════════════════════════════════
  const gitDir = join(directory, ".git")
  if (!existsSync(gitDir)) {
    log("SKIPPED: No .git directory found", { directory })
    return {} // Return empty hooks - plugin does nothing
  }
  
  // ═══════════════════════════════════════════════════════════════
  // STEP 1: Scan .env files and collect sensitive vars
  // ═══════════════════════════════════════════════════════════════
  
  // Scan .env* files up to 2 levels deep
  const envFiles = await scanEnvFiles(directory, 2)
  
  for (const filePath of envFiles) {
    const vars = await parseEnvFile(filePath)
    for (const [key, value] of Object.entries(vars)) {
      // Track ALL var names for system prompt (AI can't read .env anymore)
      allEnvVarNames.add(key)
      
      // Only REDACT vars with sensitive-looking names (and not excluded)
      if (isSensitiveKey(key, SENSITIVE_PATTERNS) && value.length > 0 && !EXCLUDED_VARS.has(key)) {
        sensitiveVars.set(key, value)
      }
      
      // Extract and redact passwords from database connection strings
      // e.g., DATABASE_URL=postgres://user:PASSWORD@host:port/db
      const dbPassword = extractDbPassword(value)
      if (dbPassword) {
        sensitiveVars.set(`${key}_PASSWORD`, dbPassword)
      }
      
      // ═══════════════════════════════════════════════════════════
      // Export ALL vars to process.env so bash PTYs inherit them
      // ═══════════════════════════════════════════════════════════
      if (!process.env[key] && value.length > 0) {
        process.env[key] = value
      }
    }
  }
  
  // Also check existing process.env for sensitive vars
  for (const [key, value] of Object.entries(process.env)) {
    if (value && isSensitiveKey(key, SENSITIVE_PATTERNS) && !sensitiveVars.has(key) && !EXCLUDED_VARS.has(key)) {
      sensitiveVars.set(key, value)
    }
  }
  
  // Create redactor function (replaces values with [ENV:VAR_NAME] and tracks what was redacted)
  const redactWithTracking = createRedactorWithTracking(sensitiveVars)
  
  // Store client for TUI messages
  _client = ctx.client
  
  // Build list of ALL var names for system prompt (AI can't read .env files)
  const availableVars = Array.from(allEnvVarNames).map(k => `$${k}`)
  
  const hooks: Hooks = {
    // ═══════════════════════════════════════════════════════════════
    // HOOK: tool.execute.after
    // Redacts sensitive values from tool outputs BEFORE they enter
    // the conversation history. This is efficient - only scans once
    // per tool call, and subsequent API calls see redacted version.
    // ═══════════════════════════════════════════════════════════════
    "tool.execute.after": async (input, output) => {
      const originalOutput = output.output
      let allRedactedVars: string[] = []
      
      // Redact sensitive values from tool output
      if (output.output && typeof output.output === "string") {
        const { result, redactedVars } = redactWithTracking(output.output)
        output.output = result
        allRedactedVars.push(...redactedVars)
      }
      
      // Also redact from title if present
      if (output.title && typeof output.title === "string") {
        const { result, redactedVars } = redactWithTracking(output.title)
        output.title = result
        allRedactedVars.push(...redactedVars)
      }
      
      // Remove duplicates
      allRedactedVars = [...new Set(allRedactedVars)]
      
      // Send TUI message if something was redacted
      if (allRedactedVars.length > 0 && _client) {
        try {
          await _client.session.promptAsync({
            path: { id: input.sessionID },
            body: {
              parts: [{
                type: "text",
                text: `[ENV PROTECTED] Environment variables ${allRedactedVars.map(v => `$${v}`).join(", ")} were redacted for security. Make sure these values don't get hardcoded in logs or code. If you think this is a mistake, ask the user via the ask tool.`,
              }],
            },
          })
        } catch {}
      }
      
      // DEBUG: Log what was redacted (so you can PROVE it works)
      if (originalOutput !== output.output) {
        log(`REDACTED [${input.tool}]`, {
          tool: input.tool,
          callID: input.callID,
          before_length: originalOutput?.length,
          after_length: output.output?.length,
          redacted: true,
          redactedVars: allRedactedVars,
          preview: output.output?.slice(0, 200),
        })
      }
    },
    
    // ═══════════════════════════════════════════════════════════════
    // HOOK: experimental.chat.system.transform
    // Adds instructions to system prompt telling AI:
    // 1. Which env vars are available (so it uses $VAR_NAME)
    // 2. Never read .env files directly
    // ═══════════════════════════════════════════════════════════════
    "experimental.chat.system.transform": async (input, output) => {
      if (availableVars.length === 0) return
      
      const instruction = `
## Environment Variables Protection

The following environment variables are pre-exported and available in bash commands:
${availableVars.join(", ")}

IMPORTANT RULES:
1. Use these variables directly (e.g., \`curl -H "Authorization: Bearer $API_KEY"\`)
2. NEVER read .env, .env.local, .env.production, .env.development or similar files containing real values
3. You CAN read .env.example files - those are safe templates
4. NEVER use cat, less, head, tail, or any tool to view actual env/secret files
4. NEVER hardcode sensitive values - always use the variable names
5. If you see [ENV:VAR_NAME was redacted] in outputs, that means the actual value was redacted for security
6. To use a redacted value, reference the original variable: $VAR_NAME

The variables are already exported - no need to run \`export\` or \`source .env\`.
`.trim()
      
      output.system.push(instruction)
    },
  }
  
  return hooks
}

// Default export for OpenCode plugin loader
export default EnvProtectPlugin
