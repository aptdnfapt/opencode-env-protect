// @bun
// src/index.ts
import { Plugin } from "@opencode/plugin";

// src/scanner.ts
import { readdir, readFile } from "fs/promises";
import { join } from "path";
async function scanEnvFiles(dir, maxDepth) {
  const envFiles = [];
  async function scan(currentDir, depth) {
    if (depth > maxDepth)
      return;
    try {
      const entries = await readdir(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(currentDir, entry.name);
        if (entry.isFile() && isEnvFile(entry.name)) {
          envFiles.push(fullPath);
        } else if (entry.isDirectory() && !isIgnoredDir(entry.name)) {
          await scan(fullPath, depth + 1);
        }
      }
    } catch {}
  }
  await scan(dir, 0);
  return envFiles;
}
function isEnvFile(filename) {
  if (filename === ".env")
    return true;
  if (filename.startsWith(".env.") && !filename.endsWith(".example"))
    return true;
  return false;
}
function isIgnoredDir(dirname) {
  const ignored = [
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "__pycache__",
    "venv",
    ".venv",
    "vendor"
  ];
  return ignored.includes(dirname) || dirname.startsWith(".");
}
async function parseEnvFile(filePath) {
  const vars = {};
  try {
    const content = await readFile(filePath, "utf-8");
    const lines = content.split(`
`);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#"))
        continue;
      const eqIndex = trimmed.indexOf("=");
      if (eqIndex === -1)
        continue;
      const key = trimmed.slice(0, eqIndex).trim();
      let value = trimmed.slice(eqIndex + 1).trim();
      if (!key || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))
        continue;
      if (value.startsWith('"') && value.endsWith('"') || value.startsWith("'") && value.endsWith("'")) {
        value = value.slice(1, -1);
      }
      if (!trimmed.slice(eqIndex + 1).trim().startsWith('"') && !trimmed.slice(eqIndex + 1).trim().startsWith("'")) {
        const commentIndex = value.indexOf(" #");
        if (commentIndex !== -1) {
          value = value.slice(0, commentIndex).trim();
        }
      }
      vars[key] = value;
    }
  } catch {}
  return vars;
}

// src/redactor.ts
function isSensitiveKey(key, patterns) {
  return patterns.some((pattern) => pattern.test(key));
}
var VALUE_BLOCKLIST = new Set([
  "true",
  "false",
  "yes",
  "no",
  "on",
  "off",
  "1",
  "0",
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "null",
  "undefined",
  "none",
  "empty",
  "nil",
  "default",
  "test",
  "dev",
  "prod",
  "staging",
  "development",
  "production",
  "id",
  "name",
  "user",
  "admin",
  "root",
  "guest",
  "postgres",
  "postgresql",
  "mysql",
  "mariadb",
  "mongodb",
  "redis",
  "password",
  "pass",
  "secret",
  "changeme",
  "letmein",
  "123456",
  "12345678",
  "qwerty",
  "abc123",
  "password123",
  "admin123",
  "root123"
]);
var DB_URL_REGEX = /^(postgres|postgresql|mysql|mongodb(\+srv)?|redis|rediss|amqp|amqps|mssql|mariadb|cockroachdb|jdbc:[a-z]+):\/\/([^:]*):([^@]+)@/i;
function extractDbPassword(value) {
  const match = value.match(DB_URL_REGEX);
  if (match && match[4]) {
    const password = match[4];
    if (password.length >= 4 && !VALUE_BLOCKLIST.has(password.toLowerCase())) {
      return password;
    }
  }
  return null;
}
var SECRET_PREFIXES = [
  "sk-",
  "sk_",
  "pk_",
  "ghp_",
  "gho_",
  "ghu_",
  "ghs_",
  "github_pat_",
  "xoxb-",
  "xoxp-",
  "xoxa-",
  "xoxr-",
  "AKIA",
  "eyJ",
  "Bearer ",
  "Basic ",
  "npm_",
  "pypi-",
  "glpat-",
  "gloas-"
];
function shouldRedactValue(value) {
  const trimmed = value.trim();
  const lower = trimmed.toLowerCase();
  if (trimmed.length < 4)
    return false;
  if (VALUE_BLOCKLIST.has(lower))
    return false;
  if (/^[\/~]/.test(trimmed) || /^[A-Za-z]:[\\\/]/.test(trimmed))
    return false;
  if (/^https?:\/\/[^@]*$/i.test(trimmed))
    return false;
  if (/^\d+$/.test(trimmed) && trimmed.length < 6)
    return false;
  if (SECRET_PREFIXES.some((prefix) => trimmed.startsWith(prefix)))
    return true;
  if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(trimmed))
    return false;
  if (trimmed.length >= 20)
    return true;
  if (trimmed.length >= 12) {
    const hasLetter = /[a-zA-Z]/.test(trimmed);
    const hasDigit = /\d/.test(trimmed);
    if (hasLetter && hasDigit)
      return true;
  }
  if (trimmed.length >= 8 && /[+\/=_-]/.test(trimmed)) {
    const hasLetter = /[a-zA-Z]/.test(trimmed);
    const hasDigit = /\d/.test(trimmed);
    if (hasLetter && hasDigit)
      return true;
  }
  return trimmed.length >= 16;
}
function createRedactorWithTracking(sensitiveVars) {
  const sortedVars = Array.from(sensitiveVars.entries()).map(([key, value]) => ({ key, value })).filter(({ value }) => shouldRedactValue(value)).sort((a, b) => b.value.length - a.value.length);
  const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns = sortedVars.map(({ key, value }) => ({
    key,
    regex: value.length < 10 ? new RegExp(`\\b${escapeRegex(value)}\\b`, "g") : new RegExp(escapeRegex(value), "g")
  }));
  return (text) => {
    let result = text;
    const redactedVars = [];
    for (const { key, regex } of patterns) {
      regex.lastIndex = 0;
      if (regex.test(result)) {
        redactedVars.push(key);
        regex.lastIndex = 0;
        result = result.replace(regex, `[ENV:${key} was redacted]`);
      }
    }
    return { result, redactedVars };
  };
}

// src/index.ts
import { appendFileSync, existsSync } from "fs";
import { basename as basename2, join as join2 } from "path";
import { tmpdir } from "os";
var DEBUG = process.env.OPENCODE_ENV_PROTECT_DEBUG === "1";
var LOG_FILE = join2(process.env.HOME || process.env.USERPROFILE || tmpdir(), ".opencode-env-protect.log");
function log(msg, data) {
  if (!DEBUG)
    return;
  const timestamp = new Date().toISOString();
  const line = data ? `[${timestamp}] ${msg}: ${JSON.stringify(data, null, 2)}
` : `[${timestamp}] ${msg}
`;
  try {
    appendFileSync(LOG_FILE, line);
  } catch {}
}
var SENSITIVE_PATTERNS = [
  /KEY/i,
  /SECRET/i,
  /TOKEN/i,
  /PASSWORD/i,
  /PASSWD/i,
  /PRIVATE/i,
  /CREDENTIAL/i,
  /AUTH/i,
  /CERT/i
];
var EXCLUDED_VARS = new Set([
  "PWD",
  "OLDPWD",
  "PATH",
  "HOME",
  "USER",
  "SHELL",
  "TERM",
  "LANG",
  "EDITOR",
  "PAGER"
]);
var SAFE_ENV_RE = /^\.env\.(?:example|sample|template|dist|defaults?|schema)$/i;
var SOURCE_EXT_RE = /\.(?:ts|tsx|js|jsx|mjs|cjs|json|ya?ml|toml|md)$/i;
async function collectEnvState(directory) {
  if (!existsSync(join2(directory, ".git"))) {
    log("SKIPPED: No .git found", { directory });
    return null;
  }
  const vars = new Map;
  const sensitive = new Map;
  const envFiles = await scanEnvFiles(directory, 2);
  for (const filePath of envFiles) {
    const parsed = await parseEnvFile(filePath);
    for (const [key, value] of Object.entries(parsed)) {
      vars.set(key, value);
      if (isSensitiveKey(key, SENSITIVE_PATTERNS) && value.length > 0 && !EXCLUDED_VARS.has(key)) {
        sensitive.set(key, value);
      }
      const dbPassword = extractDbPassword(value);
      if (dbPassword)
        sensitive.set(`${key}_PASSWORD`, dbPassword);
    }
  }
  for (const [key, value] of Object.entries(process.env)) {
    if (value && isSensitiveKey(key, SENSITIVE_PATTERNS) && !sensitive.has(key)) {
      sensitive.set(key, value);
    }
  }
  return { vars, sensitive };
}
function buildInstruction(names) {
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
`.trim();
}
function isProtectedEnvFile(filePath) {
  const name = basename2(filePath).toLowerCase();
  if (SAFE_ENV_RE.test(name))
    return false;
  if (SOURCE_EXT_RE.test(name))
    return false;
  return name === ".env" || name.startsWith(".env.") || name.endsWith(".env") || name.includes(".env.");
}
function protectedPathFromInput(input) {
  if (!input || typeof input !== "object")
    return;
  const args = input;
  for (const key of ["filePath", "path", "file_path"]) {
    const candidate = args[key];
    if (typeof candidate === "string" && isProtectedEnvFile(candidate))
      return candidate;
  }
  if (Array.isArray(args.paths)) {
    for (const candidate of args.paths) {
      if (typeof candidate === "string" && isProtectedEnvFile(candidate))
        return candidate;
    }
  }
  if (typeof args.patch === "string") {
    for (const line of args.patch.split(/\r?\n/)) {
      const match = line.match(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+?)\s*$/);
      if (match && isProtectedEnvFile(match[1]))
        return match[1];
    }
  }
  return;
}
var BLOCK_MESSAGE = "Blocked by opencode-env-protect: real .env files cannot be read or edited. " + "Use $VAR_NAME in shell commands (the variables are already exported). " + "If you need to inspect structure, .env.example / .env.sample / .env.template are allowed.";
function redactDeep(value, redact, seen = new WeakSet) {
  if (typeof value === "string")
    return redact(value);
  if (Array.isArray(value))
    return value.map((item) => redactDeep(item, redact, seen));
  if (value && typeof value === "object") {
    if (seen.has(value))
      return value;
    seen.add(value);
    for (const key of Object.keys(value)) {
      value[key] = redactDeep(value[key], redact, seen);
    }
    return value;
  }
  return value;
}
async function server() {
  return {
    "tool.execute.before": async (input, output) => {
      const blocked = protectedPathFromInput(output.args);
      if (blocked)
        throw new Error(`${BLOCK_MESSAGE} (${blocked})`);
    },
    "tool.execute.after": async (input, output) => {
      const redact = createRedactorWithTracking(currentState.sensitive);
      const redactedVars = [];
      if (output.output && typeof output.output === "string") {
        const { result, redactedVars: vars } = redact(output.output);
        output.output = result;
        redactedVars.push(...vars);
      }
      if (output.title && typeof output.title === "string") {
        const { result, redactedVars: vars } = redact(output.title);
        output.title = result;
        redactedVars.push(...vars);
      }
      const unique = [...new Set(redactedVars)];
      if (unique.length > 0) {
        log(`REDACTED [${input.tool}]`, {
          tool: input.tool,
          callID: input.callID,
          redactedVars: unique
        });
      }
    },
    "experimental.chat.system.transform": async (_input, output) => {
      const names = [...currentState.vars.keys()];
      if (names.length === 0)
        return;
      if (output.system.some((part) => part.includes("## Environment Variables Protection")))
        return;
      output.system.push(buildInstruction(names));
    }
  };
}
var EnvProtectPlugin = Plugin.define({
  id: "env-protect",
  async setup(ctx) {
    const directory = ctx.location.project?.canonical ?? ctx.location.directory;
    const state = await collectEnvState(directory);
    if (!state)
      return;
    currentState = state;
    const names = [...state.vars.keys()];
    const notify = ctx.options?.notify === true;
    await ctx.shell.hook("create.before", (event) => {
      for (const [name, value] of state.vars) {
        if (event.env[name] === undefined)
          event.env[name] = value;
      }
    });
    await ctx.tool.hook("execute.before", (event) => {
      const blocked = protectedPathFromInput(event.input);
      if (blocked)
        throw new Error(`${BLOCK_MESSAGE} (${blocked})`);
    });
    await ctx.tool.hook("execute.after", async (event) => {
      if (event.status !== "completed" || !event.result)
        return;
      const redactWithTracking = createRedactorWithTracking(state.sensitive);
      const redactedVars = [];
      const scrub = (text) => {
        const { result, redactedVars: vars } = redactWithTracking(text);
        redactedVars.push(...vars);
        return result;
      };
      const result = event.result;
      if (typeof result.content === "string")
        result.content = scrub(result.content);
      else if (Array.isArray(result.content)) {
        result.content = redactDeep(result.content, scrub);
      }
      if (typeof result.output === "string")
        result.output = scrub(result.output);
      else if (result.output != null)
        result.output = redactDeep(result.output, scrub);
      if (result.metadata != null)
        result.metadata = redactDeep(result.metadata, scrub);
      const unique = [...new Set(redactedVars)];
      if (unique.length === 0)
        return;
      log(`REDACTED [${event.tool}]`, {
        tool: event.tool,
        id: event.id,
        redactedVars: unique
      });
      if (!notify)
        return;
      try {
        await ctx.session.synthetic({
          sessionID: event.sessionID,
          text: `[ENV PROTECTED] Environment variables ${unique.map((v) => `$${v}`).join(", ")} ` + "were redacted for security. Do not hardcode these values in logs or code."
        });
      } catch {}
    });
    if (names.length > 0) {
      await ctx.session.hook("context", (event) => {
        const alreadyPresent = event.system.some((part) => part.type === "text" && typeof part.text === "string" && part.text.includes("## Environment Variables Protection"));
        if (alreadyPresent)
          return;
        event.system.push({ type: "text", text: buildInstruction(names) });
      });
    }
    log("loaded", {
      directory,
      files: names.length,
      sensitive: state.sensitive.size
    });
    return () => log("unloaded");
  }
});
var currentState = { vars: new Map, sensitive: new Map };
var src_default = {
  ...EnvProtectPlugin,
  async server() {
    const directory = process.cwd();
    const state = await collectEnvState(directory);
    if (!state)
      return {};
    currentState = state;
    for (const [key, value] of state.vars) {
      if (value.length > 0 && !process.env[key])
        process.env[key] = value;
    }
    return server();
  }
};
export {
  EnvProtectPlugin,
  src_default as default
};
