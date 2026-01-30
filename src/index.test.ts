import { describe, test, expect, beforeAll } from "bun:test"
import { scanEnvFiles, parseEnvFile } from "./scanner"
import { isSensitiveKey, createRedactor } from "./redactor"
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
      ["API_KEY", "secret123"],
      ["TOKEN", "mytoken456"],
    ])
    const redact = createRedactor(vars)
    
    const input = "Connected with key secret123 and token mytoken456"
    const output = redact(input)
    
    expect(output).toBe("Connected with key [ENV:API_KEY] and token [ENV:TOKEN]")
  })
  
  test("createRedactor handles partial matches", () => {
    const vars = new Map([
      ["API_KEY", "abc123"],
    ])
    const redact = createRedactor(vars)
    
    const input = "Error: prefix_abc123_suffix failed"
    const output = redact(input)
    
    expect(output).toBe("Error: prefix_[ENV:API_KEY]_suffix failed")
  })
  
  test("createRedactor handles overlapping values (longer first)", () => {
    const vars = new Map([
      ["SHORT_KEY", "abc"],
      ["LONG_KEY", "abcdef"],
    ])
    const redact = createRedactor(vars)
    
    // "abcdef" should be replaced as LONG_KEY, not partially as SHORT_KEY
    const input = "Value is abcdef here"
    const output = redact(input)
    
    expect(output).toBe("Value is [ENV:LONG_KEY] here")
  })
  
  test("createRedactor skips very short values", () => {
    const vars = new Map([
      ["SHORT", "ab"], // Too short (< 3 chars)
      ["VALID", "abc123"],
    ])
    const redact = createRedactor(vars)
    
    const input = "Short ab and valid abc123"
    const output = redact(input)
    
    // "ab" should NOT be replaced (too short, false positive risk)
    expect(output).toBe("Short ab and valid [ENV:VALID]")
  })
  
  test("createRedactor handles regex special characters", () => {
    const vars = new Map([
      ["REGEX_KEY", "test.value+special$chars"],
    ])
    const redact = createRedactor(vars)
    
    const input = "Found: test.value+special$chars in output"
    const output = redact(input)
    
    expect(output).toBe("Found: [ENV:REGEX_KEY] in output")
  })
})
