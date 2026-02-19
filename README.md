# opencode-env-protect

An OpenCode plugin that prevents environment variables from being leaked to AI models.

## What It Does

1. **Scans `.env` files** → Finds all environment variables in your project
2. **Auto-exports variables** → Makes them available in bash commands without manual `export`
3. **Redacts sensitive values** → Replaces actual values with `[ENV:VAR_NAME was redacted]` in tool outputs
4. **Extracts DB passwords** → Detects and redacts passwords embedded in database connection strings
5. **Instructs the AI** → Tells AI which variables exist and to never read `.env` files

## Installation

Add to your OpenCode config (`~/.config/opencode/opencode.json`):

```json
{
  "plugin": ["opencode-env-protect"]
}
```

That's it! OpenCode will auto-install from npm on next launch.

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

When the plugin loads, it does `process.env[key] = value` for every variable found in `.env` files.

**Why this works:**
```
Your shell
    ↓ spawns
OpenCode process (plugin sets process.env.API_KEY = "secret")
    ↓ spawns
Bash PTY (inherits process.env → $API_KEY is available)
```

Child processes inherit environment variables from their parent. So:
- Plugin adds vars to OpenCode's `process.env`
- When AI runs bash commands, those bash PTYs inherit the vars
- AI can use `$VAR_NAME` directly - no `export` or `source .env` needed

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
│  5. Export ALL vars to process.env                          │
│  6. Build smart redactor with heuristics                     │
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
│         Hook: experimental.chat.system.transform             │
├─────────────────────────────────────────────────────────────┤
│  Appends to system prompt:                                   │
│  - List of available $VAR_NAME variables                    │
│  - Instructions to never read .env files                    │
│  - How to interpret [ENV:X was redacted] tags               │
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
├── index.ts      # Main plugin - hooks, git check, auto-export
├── scanner.ts    # .env file discovery and parsing
├── redactor.ts   # Smart value replacement with heuristics
└── index.test.ts # Tests
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

## License

MIT
