# opencode-env-protect

An OpenCode plugin that prevents environment variables from being leaked to AI models.

## What It Does

1. **Scans `.env` files** → Finds all environment variables in your project
2. **Auto-exports variables** → Makes them available in bash commands without manual `export`
3. **Redacts sensitive values** → Replaces actual values with `[ENV:VAR_NAME]` in tool outputs
4. **Instructs the AI** → Tells AI which variables exist and to never read `.env` files

## Installation

### Option 1: Local file (recommended for testing)

1. Build the plugin:
```bash
cd opencode-env-protect
bun install
bun build src/index.ts --outfile dist/opencode-env-protect.js --target bun
```

2. Add to your OpenCode config (`~/.config/opencode/opencode.json`):
```json
{
  "plugin": ["file:///path/to/opencode-env-protect/dist/opencode-env-protect.js"]
}
```

### Option 2: npm (when published)

```json
{
  "plugin": ["opencode-env-protect"]
}
```

## How It Works

### 1. Environment Scanning

On plugin load, scans for `.env*` files up to 2 directories deep:
- `.env`
- `.env.local`
- `.env.development`
- `.env.production`
- `subdir/.env`
- etc.

**Ignored directories**: `node_modules`, `.git`, `dist`, `build`, etc.

### 2. Variable Export

All variables from `.env` files are exported to `process.env`. This means:
- Child processes (bash PTYs) inherit these variables
- AI can use `$VAR_NAME` syntax without running `export` first

```bash
# AI can just run this - no export needed
curl -H "Authorization: Bearer $API_KEY" https://api.example.com
```

### 3. Value Redaction

When a tool (bash, read, etc.) returns output, the plugin scans for sensitive values and replaces them.

**Before AI sees it:**
```
Connected with key sk-abc123secret
```

**After redaction:**
```
Connected with key [ENV:API_KEY]
```

Only variables with sensitive-looking names are redacted:
- `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`
- `API`, `PRIVATE`, `CREDENTIAL`, `AUTH`, `CERT`

**Excluded from redaction** (false positives):
- `PWD`, `OLDPWD`, `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG`, `EDITOR`, `PAGER`

### 4. System Prompt Injection

Adds instructions to the AI's system prompt:

```
## Environment Variables Protection

The following environment variables are pre-exported and available in bash commands:
$API_KEY, $DATABASE_URL, $SECRET_TOKEN, ...

IMPORTANT RULES:
1. Use these variables directly (e.g., `curl -H "Authorization: Bearer $API_KEY"`)
2. NEVER read .env, .env.local, .env.production, .env.development or similar files
3. You CAN read .env.example files - those are safe templates
4. NEVER use cat, less, head, tail, or any tool to view actual env/secret files
5. NEVER hardcode sensitive values - always use the variable names
6. If you see [ENV:VAR_NAME] in outputs, that means the actual value was redacted
7. To use a redacted value, reference the original variable: $VAR_NAME

The variables are already exported - no need to run `export` or `source .env`.
```

## Debug Mode

To verify redaction is working, enable debug logging:

```bash
export OPENCODE_ENV_PROTECT_DEBUG=1
opencode
```

Check the log file:
```bash
cat ~/.opencode-env-protect.log
```

Example output:
```
[2026-01-30T21:20:03.622Z] REDACTED [bash]: {
  "tool": "bash",
  "callID": "toolu_xyz",
  "before_length": 8,
  "after_length": 14,
  "redacted": true,
  "preview": "KEY=[ENV:KEY]\n"
}
```

This proves:
- `before_length` vs `after_length` → something changed
- `preview` → shows the redacted output (safe to log)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Plugin Load                              │
├─────────────────────────────────────────────────────────────┤
│  1. Scan .env* files (2 levels deep)                        │
│  2. Parse key=value pairs                                    │
│  3. Export ALL vars to process.env                          │
│  4. Build redactor for sensitive vars                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Hook: tool.execute.after                        │
├─────────────────────────────────────────────────────────────┤
│  Tool runs (bash, read, etc.)                               │
│           │                                                  │
│           ▼                                                  │
│  Output: "Error: invalid key sk-abc123"                     │
│           │                                                  │
│           ▼ (redactor)                                       │
│  Output: "Error: invalid key [ENV:API_KEY]"                 │
│           │                                                  │
│           ▼                                                  │
│  AI receives redacted output                                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│         Hook: experimental.chat.system.transform             │
├─────────────────────────────────────────────────────────────┤
│  Appends to system prompt:                                   │
│  - List of available $VAR_NAME variables                    │
│  - Instructions to never read .env files                    │
│  - How to interpret [ENV:X] tags                            │
└─────────────────────────────────────────────────────────────┘
```

## Hooks Used

| Hook | Purpose |
|------|---------|
| `tool.execute.after` | Redacts sensitive values from tool outputs before AI sees them |
| `experimental.chat.system.transform` | Adds env var list and safety instructions to system prompt |

## File Structure

```
src/
├── index.ts      # Main plugin - hooks + auto-export logic
├── scanner.ts    # .env file discovery and parsing
├── redactor.ts   # Value replacement logic
└── index.test.ts # Tests
```

## Limitations

1. **Minimum value length**: Values shorter than 3 characters are not redacted (to avoid false positives)
2. **Pattern-based detection**: Only vars matching sensitive patterns are redacted - a var named `MY_DATA` won't be redacted even if it contains secrets
3. **Scan depth**: Only scans 2 levels deep by default

## License

MIT
