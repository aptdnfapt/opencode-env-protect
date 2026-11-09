# opencode-env-protect

An OpenCode plugin that prevents environment variables from being leaked to AI models.
Works with **OpenCode 1** and **OpenCode 2**.

## What It Does

1. **Scans `.env` files** → Finds all environment variables in your project
2. **Auto-exports variables** → Makes them available in shell commands without manual `export`
3. **Blocks env file access** → Read/edit/write/grep/patch tools cannot touch real `.env` files (OpenCode 2)
4. **Redacts sensitive values** → Replaces actual values with `[ENV:VAR_NAME was redacted]` in tool outputs
5. **Extracts DB passwords** → Detects and redacts passwords embedded in database connection strings
6. **Instructs the AI** → Tells AI which variables exist and to never read `.env` files

## Installation

**OpenCode 2** (uses `plugins`, plural):

```json
{
  "plugins": ["opencode-env-protect"]
}
```

**OpenCode 1** (uses `plugin`, singular; OpenCode 2 still accepts this legacy key):

```json
{
  "plugin": ["opencode-env-protect"]
}
```

That's it! OpenCode will auto-install from npm on next launch.

Requires OpenCode `1.18.29+` (V1 object entrypoint) or any `2.x` release.
The package depends on `@opencode/plugin` and is bundled with `bun build`.

## How It Works

### 1. Git Repository Check

**Plugin only activates in git repositories.** If no `.git` directory exists, the plugin does nothing. This prevents accidental redaction in random directories.

### 2. Environment Scanning

On plugin load, scans for `.env*` files up to 2 directories deep:
- `.env`
- `.env.local`
- `.env.development`
- `.env.production`
- `subdir/.env`
- etc.

**Ignored directories**: `node_modules`, `.git`, `dist`, `build`, etc.

### 3. Variable Export (How it works)

Every variable found in `.env` files is made available to shell commands.

- **OpenCode 2**: the plugin registers a `shell.create.before` hook and adds the variables to each command's `env`. Nothing is written to the server's global `process.env`.
- **OpenCode 1**: the plugin sets `process.env[key] = value`; bash PTYs inherit it from the OpenCode process.

Either way:
- When AI runs shell commands, `$VAR_NAME` is already set
- AI can use `$VAR_NAME` directly - no `export` or `source .env` needed
- Existing values in your environment are never overwritten

```bash
# AI can just run this - vars already available
curl -H "Authorization: Bearer $API_KEY" https://api.example.com

# No need for this:
# export API_KEY=... && curl ...
# source .env && curl ...
```

**System prompt tells AI** which variables exist (since it can't read `.env` files anymore).

### 4. Smart Value Redaction

When a tool (bash, read, etc.) returns output, the plugin scans for sensitive values and replaces them.

**Before AI sees it:**
```
Connected with key sk-abc123secret
```

**After redaction:**
```
Connected with key [ENV:API_KEY was redacted]
```

#### Sensitive Key Patterns

Only variables with sensitive-looking names are redacted:
- `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`
- `PRIVATE`, `CREDENTIAL`, `AUTH`, `CERT`

#### Smart Value Heuristics

Not all values are redacted. The plugin uses heuristics to avoid false positives:

**Values that are SKIPPED (never redacted):**
- Booleans: `true`, `false`, `yes`, `no`, `on`, `off`
- Common hosts: `localhost`, `127.0.0.1`, `0.0.0.0`
- Null-ish: `null`, `undefined`, `none`
- Common defaults: `development`, `production`, `staging`
- Short pure numbers: `8080`, `3000`, `443` (ports, timeouts)
- Paths: `/home/user`, `~/config`
- URLs without auth: `https://api.example.com`
- Common DB passwords: `postgres`, `mysql`, `password`, `changeme`, etc.

**Values that ARE redacted:**
- Known secret prefixes: `sk-`, `ghp_`, `xoxb-`, `AKIA`, `eyJ` (JWT), etc.
- Long values (≥20 chars)
- Medium values (≥12 chars) with mixed letters + digits
- Values with special chars common in secrets

#### Word Boundary Protection

Short values (<10 chars) use word boundary matching to prevent partial replacements:
```
API_KEY=secret123
Text: "my_secret123_var"  → NOT redacted (no word boundary)
Text: "key is secret123"  → REDACTED (word boundary match)
```

Long values (≥10 chars) use substring matching since real secrets are usually long.

### 5. Database Password Extraction

Automatically extracts and redacts passwords from database connection strings:

```
DATABASE_URL=postgres://user:MySecretPass123@host:5432/db
                            ^^^^^^^^^^^^^^
                            This gets extracted and redacted
```

**Supported protocols:**
- PostgreSQL: `postgres://`, `postgresql://`
- MySQL: `mysql://`, `mariadb://`
- MongoDB: `mongodb://`, `mongodb+srv://`
- Redis: `redis://`, `rediss://`
- RabbitMQ: `amqp://`, `amqps://`
- MSSQL: `mssql://`
- CockroachDB: `cockroachdb://`
- JDBC: `jdbc:postgresql://`, etc.

**Example:**
```
Original output:
"Connected to postgres://admin:xK9mZ2pL5@db.example.com:5432/myapp"

After redaction:
"Connected to postgres://admin:[ENV:DATABASE_URL_PASSWORD was redacted]@db.example.com:5432/myapp"
```

**Note:** Common default passwords like `postgres`, `mysql`, `password` are NOT redacted to avoid false positives everywhere in your codebase.

### 6. Chat Notification

When redaction happens, a detailed message appears in the chat:

```
[ENV PROTECTED] Environment variables $API_KEY, $SECRET_TOKEN were redacted for security. 
Make sure these values don't get hardcoded in logs or code. 
If you think this is a mistake, ask the user via the ask tool.
```

### 7. System Prompt Injection

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
6. If you see [ENV:VAR_NAME was redacted] in outputs, that means the actual value was redacted
7. To use a redacted value, reference the original variable: $VAR_NAME

The variables are already exported - no need to run `export` or `source .env`.
```

### 8. Env File Access Blocking (OpenCode 2)

Real env files cannot be read or edited through the file-oriented tools:

- `read`, `edit`, `write`, `grep` when the path points at `.env`, `.env.*`, `*.env`, or `*.env.*`
- `patch` / `apply_patch` when a patch header names a protected file

Protected:
- `.env`, `.env.local`, `.env.production`, `api.env`, `config.env.local`

Allowed:
- `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults`
- Source files such as `app.env.ts`

Blocked calls throw an error that tells the model to use `$VAR_NAME` instead.
OpenCode 1 gets the equivalent `tool.execute.before` hook.

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
  "redactedVars": ["API_KEY"],
  "preview": "KEY=[ENV:API_KEY was redacted]\n"
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Plugin Load                              │
├─────────────────────────────────────────────────────────────┤
│  1. Check for .git directory (skip if not a repo)           │
│  2. Scan .env* files (2 levels deep)                        │
│  3. Parse key=value pairs                                    │
│  4. Extract DB passwords from connection strings             │
│  5. Export vars (shell hook in V2, process.env in V1)        │
│  6. Build smart redactor with heuristics                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│         Hook: tool.execute.before / execute.before           │
├─────────────────────────────────────────────────────────────┤
│  Blocks read/edit/write/grep/patch on real .env files        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│         Hook: tool.execute.after / execute.after             │
├─────────────────────────────────────────────────────────────┤
│  Tool runs (bash, read, etc.)                               │
│           │                                                  │
│           ▼                                                  │
│  Output: "Error: invalid key sk-abc123"                     │
│           │                                                  │
│           ▼ (smart redactor)                                 │
│  - Check value heuristics (skip common values)              │
│  - Use word boundary for short values                        │
│  - Replace with [ENV:VAR_NAME was redacted]                 │
│           │                                                  │
│           ▼                                                  │
│  AI receives redacted output                                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│     Hook: experimental.chat.system.transform / context       │
├─────────────────────────────────────────────────────────────┤
│  Appends to system prompt:                                   │
│  - List of available $VAR_NAME variables                    │
│  - Instructions to never read .env files                    │
│  - How to interpret [ENV:X was redacted] tags               │
└─────────────────────────────────────────────────────────────┘
```

## Hooks Used

| OpenCode 1 | OpenCode 2 | Purpose |
|---|---|---|
| `tool.execute.before` | `ctx.tool.hook("execute.before")` | Blocks read/edit/write/grep/patch on env files |
| `tool.execute.after` | `ctx.tool.hook("execute.after")` | Redacts sensitive values before AI sees them |
| `shell.env` | `ctx.shell.hook("create.before")` | Injects variables into shell commands |
| `experimental.chat.system.transform` | `ctx.session.hook("context")` | Adds env var list and safety instructions |

V2 chat notifications use `ctx.session.synthetic` and are opt-in:

```jsonc
{
  "plugins": [
    { "package": "opencode-env-protect", "options": { "notify": true } }
  ]
}
```

## File Structure

```
src/
├── index.ts        # Dual V1 + V2 entrypoint, hooks, git check, auto-export
├── scanner.ts      # .env file discovery and parsing
├── redactor.ts     # Smart value replacement with heuristics
├── index.test.ts   # Scanner + redactor tests
└── plugin.test.ts  # V2 entrypoint/hook tests
```

## What Gets Redacted vs Skipped

### Redacted ✓
| Example | Why |
|---------|-----|
| `sk-abc123xyz` | Known secret prefix (`sk-`) |
| `ghp_xxxxxxxxxxxx` | GitHub token prefix |
| `eyJhbGciOiJIUzI1...` | JWT token prefix |
| `AKIAIOSFODNN7EXAMPLE` | AWS key prefix |
| `xK9mZ2pL5qR8nT3` | Long mixed alphanumeric |
| `secret123abc456` | Medium length + mixed chars |

### Skipped ✗
| Example | Why |
|---------|-----|
| `true`, `false` | Blocklisted boolean |
| `localhost` | Blocklisted common host |
| `8080`, `3000` | Short pure number (port) |
| `/home/user/app` | Path (starts with `/`) |
| `https://api.com` | URL without auth |
| `postgres`, `password` | Common default password |
| `development` | Blocklisted environment name |

## Limitations

1. **Git required**: Plugin only works in git repositories
2. **Pattern-based detection**: Only vars matching sensitive patterns (`KEY`, `SECRET`, etc.) are considered
3. **Scan depth**: Only scans 2 levels deep by default
4. **Heuristics not perfect**: Some edge cases may slip through or cause false positives
5. **Load-time snapshot**: Env files are read when the plugin loads. Reload OpenCode after editing them.
6. **Not a sandbox**: Shell commands that transform values (base64, split strings) can still evade redaction.
   The V2 file-tool block is a guardrail, not an OS-level restriction.

## License

MIT
