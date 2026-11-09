import { Plugin } from "@opencode/plugin"
import { scanEnvFiles, parseEnvFile } from "./scanner"
import { isSensitiveKey, createRedactorWithTracking, extractDbPassword } from "./redactor"
import { appendFileSync, existsSync } from "node:fs"
import { basename, join } from "node:path"
import { tmpdir } from "node:os"

// ═══════════════════════════════════════════════════════════════
// DEBUG LOGGING - writes to ~/.opencode-env-protect.log
// Set OPENCODE_ENV_PROTECT_DEBUG=1 to enable
// ═══════════════════════════════════════════════════════════════
const DEBUG = process.env.OPENCODE_ENV_PROTECT_DEBUG === "1"
const LOG_FILE = join(
  process.env.HOME || process.env.USERPROFILE || tmpdir(),
  ".opencode-env-protect.log",
)

function log(msg: string, data?: unknown) {
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
  "PWD", // current working directory
  "OLDPWD", // previous directory
  "PATH", // system path
  "HOME", // home directory
  "USER", // username
  "SHELL", // shell path
  "TERM", // terminal type
  "LANG", // language
  "EDITOR", // editor
  "PAGER", // pager
])

const SAFE_ENV_RE = /^\.env\.(?:example|sample|template|dist|defaults?|schema)$/i
const SOURCE_EXT_RE = /\.(?:ts|tsx|js|jsx|mjs|cjs|json|ya?ml|toml|md)$/i

// ═══════════════════════════════════════════════════════════════
// Shared state, built once per plugin instance
// ═══════════════════════════════════════════════════════════════
interface EnvState {
  /** name -> value, used for shell export and the system prompt */
  vars: Map<string, string>
  /** name -> value, used by the redactor */
  sensitive: Map<string, string>
}

async function collectEnvState(directory: string): Promise<EnvState | null> {
  // GATE: only activate inside a git repository.
  // Worktrees use a `.git` file, so existsSync covers both shapes.
  if (!existsSync(join(directory, ".git"))) {
    log("SKIPPED: No .git found", { directory })
    return null
  }

  const vars = new Map<string, string>()
  const sensitive = new Map<string, string>()

  const envFiles = await scanEnvFiles(directory, 2)

  for (const filePath of envFiles) {
    const parsed = await parseEnvFile(filePath)
    for (const [key, value] of Object.entries(parsed)) {
      vars.set(key, value)

      if (
        isSensitiveKey(key, SENSITIVE_PATTERNS) &&
        value.length > 0 &&
        !EXCLUDED_VARS.has(key)
      ) {
        sensitive.set(key, value)
      }

      // Extract and redact passwords from database connection strings
      // e.g. DATABASE_URL=postgres://user:PASSWORD@host:port/db
      const dbPassword = extractDbPassword(value)
      if (dbPassword) sensitive.set(`${key}_PASSWORD`, dbPassword)
    }
  }

  // Also protect sensitive vars already present in the process environment.
  for (const [key, value] of Object.entries(process.env)) {
    if (value && isSensitiveKey(key, SENSITIVE_PATTERNS) && !sensitive.has(key)) {
      sensitive.set(key, value)
    }
  }

  return { vars, sensitive }
}

function buildInstruction(names: string[]): string {
  return `
## Environment Variables Protection

The following environment variables are pre-exported and available in shell commands:
${names.map((name) => `$${name}`).join(", ")}

IMPORTANT RULES:
1. Use these variables directly (e.g., \`curl -H "Authorization: Bearer $API_KEY"\`)
2. NEVER read .env, .env.local, .env.production, .env.development or similar files containing real values
3. You CAN read .env.example, .env.sample and .env.template - those are safe templates
4. NEVER use cat, less, head, tail, or any tool to view actual env/secret files
5. NEVER hardcode sensitive values - always use the variable names
6. If you see [ENV:VAR_NAME was redacted] in outputs, the actual value was redacted for security
7. To use a redacted value, reference the original variable: $VAR_NAME

The variables are already exported - no need to run \`export\` or \`source .env\`.
`.trim()
}

// ═══════════════════════════════════════════════════════════════
// File protection helpers (V2 hooks)
// ═══════════════════════════════════════════════════════════════
function isProtectedEnvFile(filePath: string): boolean {
  const name = basename(filePath).toLowerCase()
  if (SAFE_ENV_RE.test(name)) return false
  // Do not treat source files such as `app.env.ts` as dotenv files.
  if (SOURCE_EXT_RE.test(name)) return false
  return (
    name === ".env" ||
    name.startsWith(".env.") ||
    name.endsWith(".env") ||
    name.includes(".env.")
  )
}

function protectedPathFromInput(input: unknown): string | undefined {
  if (!input || typeof input !== "object") return undefined
  const args = input as Record<string, unknown>

  for (const key of ["filePath", "path", "file_path"]) {
    const candidate = args[key]
    if (typeof candidate === "string" && isProtectedEnvFile(candidate)) return candidate
  }

  if (Array.isArray(args.paths)) {
    for (const candidate of args.paths) {
      if (typeof candidate === "string" && isProtectedEnvFile(candidate)) return candidate
    }
  }

  if (typeof args.patch === "string") {
    for (const line of args.patch.split(/\r?\n/)) {
      const match = line.match(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+?)\s*$/)
      if (match && isProtectedEnvFile(match[1])) return match[1]
    }
  }

  return undefined
}

const BLOCK_MESSAGE =
  "Blocked by opencode-env-protect: real .env files cannot be read or edited. " +
  "Use $VAR_NAME in shell commands (the variables are already exported). " +
  "If you need to inspect structure, .env.example / .env.sample / .env.template are allowed."

function redactDeep(
  value: unknown,
  redact: (text: string) => string,
  seen = new WeakSet<object>(),
): unknown {
  if (typeof value === "string") return redact(value)
  if (Array.isArray(value)) return value.map((item) => redactDeep(item, redact, seen))
  if (value && typeof value === "object") {
    if (seen.has(value)) return value
    seen.add(value)
    for (const key of Object.keys(value)) {
      ;(value as Record<string, unknown>)[key] = redactDeep(
        (value as Record<string, unknown>)[key],
        redact,
        seen,
      )
    }
    return value
  }
  return value
}

// ═══════════════════════════════════════════════════════════════
// V1 implementation (OpenCode 1.18.29+)
// ═══════════════════════════════════════════════════════════════
async function server() {
  return {
    "tool.execute.before": async (input: { tool: string }, output: { args: unknown }) => {
      const blocked = protectedPathFromInput(output.args)
      if (blocked) throw new Error(`${BLOCK_MESSAGE} (${blocked})`)
    },

    "tool.execute.after": async (
      input: { tool: string; sessionID: string; callID: string },
      output: { output?: string; title?: string },
    ) => {
      const redact = createRedactorWithTracking(currentState.sensitive)
      const redactedVars: string[] = []

      if (output.output && typeof output.output === "string") {
        const { result, redactedVars: vars } = redact(output.output)
        output.output = result
        redactedVars.push(...vars)
      }

      if (output.title && typeof output.title === "string") {
        const { result, redactedVars: vars } = redact(output.title)
        output.title = result
        redactedVars.push(...vars)
      }

      const unique = [...new Set(redactedVars)]
      if (unique.length > 0) {
        log(`REDACTED [${input.tool}]`, {
          tool: input.tool,
          callID: input.callID,
          redactedVars: unique,
        })
      }
    },

    "experimental.chat.system.transform": async (
      _input: unknown,
      output: { system: string[] },
    ) => {
      const names = [...currentState.vars.keys()]
      if (names.length === 0) return
      if (output.system.some((part) => part.includes("## Environment Variables Protection"))) return
      output.system.push(buildInstruction(names))
    },
  }
}

// ═══════════════════════════════════════════════════════════════
// V2 implementation (OpenCode 2.x)
// ═══════════════════════════════════════════════════════════════
export const EnvProtectPlugin = Plugin.define({
  id: "env-protect",
  async setup(ctx) {
    const directory = ctx.location.project?.canonical ?? ctx.location.directory
    const state = await collectEnvState(directory)
    if (!state) return

    currentState = state

    const names = [...state.vars.keys()]
    const notify = (ctx.options as Record<string, unknown> | undefined)?.notify === true

    // Export vars to shell commands without overwriting the user's environment.
    await ctx.shell.hook("create.before", (event) => {
      for (const [name, value] of state.vars) {
        if (event.env[name] === undefined) event.env[name] = value
      }
    })

    // Block file tools from touching real env files.
    await ctx.tool.hook("execute.before", (event) => {
      const blocked = protectedPathFromInput(event.input)
      if (blocked) throw new Error(`${BLOCK_MESSAGE} (${blocked})`)
    })

    // Redact secrets from every tool result before it reaches the model.
    await ctx.tool.hook("execute.after", async (event) => {
      if (event.status !== "completed" || !event.result) return

      const redactWithTracking = createRedactorWithTracking(state.sensitive)
      const redactedVars: string[] = []

      const scrub = (text: string) => {
        const { result, redactedVars: vars } = redactWithTracking(text)
        redactedVars.push(...vars)
        return result
      }

      const result = event.result as {
        content?: string | unknown[]
        output?: unknown
        metadata?: unknown
      }

      if (typeof result.content === "string") result.content = scrub(result.content)
      else if (Array.isArray(result.content)) {
        result.content = redactDeep(result.content, scrub) as unknown[]
      }

      if (typeof result.output === "string") result.output = scrub(result.output)
      else if (result.output != null) result.output = redactDeep(result.output, scrub)

      if (result.metadata != null) result.metadata = redactDeep(result.metadata, scrub)

      const unique = [...new Set(redactedVars)]
      if (unique.length === 0) return

      log(`REDACTED [${event.tool}]`, {
        tool: event.tool,
        id: event.id,
        redactedVars: unique,
      })

      if (!notify) return
      try {
        await ctx.session.synthetic({
          sessionID: event.sessionID,
          text:
            `[ENV PROTECTED] Environment variables ${unique.map((v) => `$${v}`).join(", ")} ` +
            "were redacted for security. Do not hardcode these values in logs or code.",
        })
      } catch {}
    })

    // Tell the model what exists and how to behave.
    if (names.length > 0) {
      await ctx.session.hook("context", (event) => {
        const alreadyPresent = event.system.some(
          (part) =>
            part.type === "text" &&
            typeof part.text === "string" &&
            part.text.includes("## Environment Variables Protection"),
        )
        if (alreadyPresent) return
        event.system.push({ type: "text", text: buildInstruction(names) })
      })
    }

    log("loaded", {
      directory,
      files: names.length,
      sensitive: state.sensitive.size,
    })

    return () => log("unloaded")
  },
})

// ═══════════════════════════════════════════════════════════════
// Shared between the V1 and V2 entrypoints.
// V1 calls server() once per plugin instance, so its state is set
// when the V1 hook set is created by the loader.
// ═══════════════════════════════════════════════════════════════
let currentState: EnvState = { vars: new Map(), sensitive: new Map() }

/**
 * V1 entrypoint. The object form (id + setup + server) is supported by
 * OpenCode 1.18.29 and newer, and by OpenCode 2.x (which ignores server()).
 */
export default {
  ...EnvProtectPlugin,
  async server() {
    // V1 has no setup() context, so load state per location here.
    const directory = process.cwd()
    const state = await collectEnvState(directory)
    if (!state) return {}

    currentState = state

    // V1 has no shell hook: export into the process so bash PTYs inherit it.
    for (const [key, value] of state.vars) {
      if (value.length > 0 && !process.env[key]) process.env[key] = value
    }

    return server()
  },
}
