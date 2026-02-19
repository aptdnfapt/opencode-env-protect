import { describe, test, expect, beforeAll } from "bun:test"
import { scanEnvFiles, parseEnvFile } from "./scanner"
import { isSensitiveKey, createRedactor, shouldRedactValue } from "./redactor"
import { mkdtemp, writeFile, mkdir, rm } from "fs/promises"
import { join } from "path"
import { tmpdir } from "os"

describe("scanner", () => {
  let testDir: string
  
  beforeAll(async () => {
    // Create temp directory with test .env files
    testDir = await mkdtemp(join(tmpdir(), "env-protect-test-"))
    
    // Root .env
    await writeFile(join(testDir, ".env"), `
API_KEY=secret123
DATABASE_URL=postgres://user:pass@localhost/db
NORMAL_VAR=not_sensitive
`)
    
    // .env.local
    await writeFile(join(testDir, ".env.local"), `
SECRET_TOKEN=token456
`)
    
    // Subdir with .env
    await mkdir(join(testDir, "subdir"))
    await writeFile(join(testDir, "subdir", ".env"), `
PRIVATE_KEY=privatekey789
`)
    
    // Deep subdir (level 2)
    await mkdir(join(testDir, "subdir", "deep"))
    await writeFile(join(testDir, "subdir", "deep", ".env"), `
DEEP_SECRET=shouldfind
`)
    
    // Too deep (level 3) - should NOT be found with maxDepth=2
    await mkdir(join(testDir, "subdir", "deep", "tooDeep"))
    await writeFile(join(testDir, "subdir", "deep", "tooDeep", ".env"), `
TOO_DEEP_KEY=shouldnotfind
`)
  })
  
  test("scanEnvFiles finds .env files up to depth 2", async () => {
    const files = await scanEnvFiles(testDir, 2)
    
    expect(files.length).toBe(4) // .env, .env.local, subdir/.env, subdir/deep/.env
    expect(files.some(f => f.endsWith(".env"))).toBe(true)
    expect(files.some(f => f.endsWith(".env.local"))).toBe(true)
    expect(files.some(f => f.includes("subdir") && f.endsWith(".env"))).toBe(true)
    expect(files.some(f => f.includes("deep") && f.endsWith(".env"))).toBe(true)
    // Should NOT include tooDeep
    expect(files.some(f => f.includes("tooDeep"))).toBe(false)
  })
  
  test("parseEnvFile parses key=value pairs", async () => {
    const envPath = join(testDir, ".env")
    const vars = await parseEnvFile(envPath)
    
    expect(vars.API_KEY).toBe("secret123")
    expect(vars.DATABASE_URL).toBe("postgres://user:pass@localhost/db")
    expect(vars.NORMAL_VAR).toBe("not_sensitive")
  })
  
  test("parseEnvFile handles quoted values", async () => {
    const quotedEnv = join(testDir, ".env.quoted")
    await writeFile(quotedEnv, `
DOUBLE_QUOTED="hello world"
SINGLE_QUOTED='foo bar'
`)
    const vars = await parseEnvFile(quotedEnv)
    
    expect(vars.DOUBLE_QUOTED).toBe("hello world")
    expect(vars.SINGLE_QUOTED).toBe("foo bar")
  })
})

describe("redactor", () => {
  const PATTERNS = [/KEY/i, /SECRET/i, /TOKEN/i, /PASSWORD/i, /API/i]
  
  test("isSensitiveKey matches sensitive patterns", () => {
    expect(isSensitiveKey("API_KEY", PATTERNS)).toBe(true)
    expect(isSensitiveKey("secret_token", PATTERNS)).toBe(true)
    expect(isSensitiveKey("MY_PASSWORD", PATTERNS)).toBe(true)
    expect(isSensitiveKey("NORMAL_VAR", PATTERNS)).toBe(false)
    expect(isSensitiveKey("DATABASE_URL", PATTERNS)).toBe(false)
  })
  
  test("createRedactor replaces values with [ENV:VAR_NAME]", () => {
    const vars = new Map([
      ["API_KEY", "sk-secret123abcdef"],  // Long enough + has prefix
      ["TOKEN", "mytoken456xyzabc"],       // Long enough
    ])
    const redact = createRedactor(vars)
    
    const input = "Connected with key sk-secret123abcdef and token mytoken456xyzabc"
    const output = redact(input)
    
    expect(output).toBe("Connected with key [ENV:API_KEY was redacted] and token [ENV:TOKEN was redacted]")
  })
  
  test("createRedactor handles overlapping values (longer first)", () => {
    const vars = new Map([
      ["SHORT_KEY", "sk-abcdef123"],
      ["LONG_KEY", "sk-abcdef123456789"],
    ])
    const redact = createRedactor(vars)
    
    // Longer value should be replaced first
    const input = "Value is sk-abcdef123456789 here"
    const output = redact(input)
    
    expect(output).toBe("Value is [ENV:LONG_KEY was redacted] here")
  })
  
  test("createRedactor handles regex special characters", () => {
    const vars = new Map([
      ["REGEX_KEY", "sk-test.value+special$chars123"],
    ])
    const redact = createRedactor(vars)
    
    const input = "Found: sk-test.value+special$chars123 in output"
    const output = redact(input)
    
    expect(output).toBe("Found: [ENV:REGEX_KEY was redacted] in output")
  })
})

describe("shouldRedactValue", () => {
  test("skips blocklisted values", () => {
    expect(shouldRedactValue("true")).toBe(false)
    expect(shouldRedactValue("false")).toBe(false)
    expect(shouldRedactValue("localhost")).toBe(false)
    expect(shouldRedactValue("127.0.0.1")).toBe(false)
    expect(shouldRedactValue("null")).toBe(false)
    expect(shouldRedactValue("development")).toBe(false)
  })
  
  test("skips short values", () => {
    expect(shouldRedactValue("abc")).toBe(false)
    expect(shouldRedactValue("xy")).toBe(false)
    expect(shouldRedactValue("1")).toBe(false)
  })
  
  test("skips paths", () => {
    expect(shouldRedactValue("/home/user")).toBe(false)
    expect(shouldRedactValue("/etc/ssl/certs")).toBe(false)
    expect(shouldRedactValue("~/config")).toBe(false)
    expect(shouldRedactValue("C:\\Users\\test")).toBe(false)
  })
  
  test("skips URLs without auth", () => {
    expect(shouldRedactValue("https://api.example.com")).toBe(false)
    expect(shouldRedactValue("http://localhost:3000")).toBe(false)
  })
  
  test("skips short pure numbers (ports, etc)", () => {
    expect(shouldRedactValue("8080")).toBe(false)
    expect(shouldRedactValue("3000")).toBe(false)
    expect(shouldRedactValue("443")).toBe(false)
    expect(shouldRedactValue("12345")).toBe(false)
  })
  
  test("redacts known secret prefixes", () => {
    expect(shouldRedactValue("sk-abc123")).toBe(true)
    expect(shouldRedactValue("ghp_xxxxxxxxxxxx")).toBe(true)
    expect(shouldRedactValue("xoxb-123-456-abc")).toBe(true)
    expect(shouldRedactValue("AKIAIOSFODNN7EXAMPLE")).toBe(true)
    expect(shouldRedactValue("eyJhbGciOiJIUzI1NiJ9")).toBe(true)
  })
  
  test("redacts long values", () => {
    expect(shouldRedactValue("this_is_a_very_long_secret_key")).toBe(true)
    expect(shouldRedactValue("abcdefghijklmnopqrst")).toBe(true)  // 20 chars
  })
  
  test("redacts medium values with mixed chars", () => {
    expect(shouldRedactValue("secret123abc")).toBe(true)  // 12 chars, mixed
    expect(shouldRedactValue("abc123def456")).toBe(true)  // 12 chars, mixed
  })
  
  test("does not redact simple medium values", () => {
    expect(shouldRedactValue("mysimplevalue")).toBe(false)  // 13 chars but no digits
    expect(shouldRedactValue("123456789012")).toBe(false)   // 12 chars but pure digits
  })
})

describe("word boundary for short values", () => {
  test("short values use word boundary", () => {
    const vars = new Map([
      ["API_KEY", "sk-short1"],  // Short value with known prefix
    ])
    const redact = createRedactor(vars)
    
    // Should NOT match inside a longer string
    const input = "prefix_sk-short1_suffix and sk-short1 alone"
    const output = redact(input)
    
    // Only the standalone occurrence should be redacted (word boundary)
    expect(output).toContain("prefix_sk-short1_suffix")  // NOT redacted (no word boundary)
    expect(output).toContain("[ENV:API_KEY was redacted]")            // Standalone IS redacted
  })
  
  test("long values do NOT use word boundary (substring match)", () => {
    const vars = new Map([
      ["API_KEY", "sk-this_is_a_long_secret_key"],
    ])
    const redact = createRedactor(vars)
    
    // Should match inside a longer string
    const input = "prefix_sk-this_is_a_long_secret_key_suffix"
    const output = redact(input)
    
    expect(output).toBe("prefix_[ENV:API_KEY was redacted]_suffix")
  })
})
