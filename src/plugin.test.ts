import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { mkdtemp, mkdir, writeFile, rm } from "fs/promises"
import { join } from "path"
import { tmpdir } from "os"
import plugin, { EnvProtectPlugin } from "./index"

describe("V2 entrypoint", () => {
  let dir: string

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "env-protect-v2-"))
    await mkdir(join(dir, ".git"))
    await writeFile(
      join(dir, ".env"),
      [
        "API_KEY=sk-abcdef123456789",
        "DATABASE_URL=postgres://user:Sup3rSecretPass@localhost/db",
        "SAFE_URL=https://example.com",
      ].join("\n"),
    )
  })

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  test("exports a dual OpenCode 1 + 2 entrypoint", () => {
    expect(plugin.id).toBe("env-protect")
    expect(typeof plugin.setup).toBe("function")
    expect(typeof plugin.server).toBe("function")
    expect(EnvProtectPlugin.id).toBe("env-protect")
  })

  test("registers V2 hooks, blocks env files and redacts secrets", async () => {
    const hooks: Record<string, (event: any) => any> = {}

    const ctx = {
      location: { directory: dir, project: { canonical: dir } },
      options: {},
      tool: {
        hook: async (name: string, callback: (event: any) => any) => {
          hooks[name] = callback
        },
      },
      shell: {
        hook: async (name: string, callback: (event: any) => any) => {
          hooks[name] = callback
        },
      },
      session: {
        hook: async (name: string, callback: (event: any) => any) => {
          hooks[name] = callback
        },
        synthetic: async () => {},
      },
    }

    await EnvProtectPlugin.setup(ctx as any)

    expect(typeof hooks["execute.before"]).toBe("function")
    expect(typeof hooks["execute.after"]).toBe("function")
    expect(typeof hooks["context"]).toBe("function")
    expect(typeof hooks["create.before"]).toBe("function")

    // Real env files are blocked.
    let blocked = false
    try {
      await hooks["execute.before"]({ tool: "read", input: { filePath: join(dir, ".env") } })
    } catch {
      blocked = true
    }
    expect(blocked).toBe(true)

    // Templates and source files are allowed.
    await hooks["execute.before"]({ tool: "read", input: { filePath: join(dir, ".env.example") } })
    await hooks["execute.before"]({ tool: "read", input: { filePath: join(dir, "app.env.ts") } })

    // Secrets are redacted from content and nested output.
    const event = {
      status: "completed",
      tool: "shell",
      sessionID: "ses_test",
      id: "call_test",
      result: {
        content: "key=sk-abcdef123456789 db=Sup3rSecretPass",
        output: { nested: ["sk-abcdef123456789"] },
      },
    }
    await hooks["execute.after"](event)

    expect(event.result.content).toContain("[ENV:API_KEY was redacted]")
    expect(event.result.content).toContain("[ENV:DATABASE_URL_PASSWORD was redacted]")
    expect(JSON.stringify(event.result.output)).toContain("[ENV:API_KEY was redacted]")

    // System prompt lists names once.
    const system = { system: [] as Array<{ type: string; text: string }> }
    await hooks["context"](system)
    expect(system.system[0].text).toContain("$API_KEY")
    await hooks["context"](system)
    expect(system.system.length).toBe(1)

    // Shell env receives the variables.
    const shell = { env: {} as Record<string, string | undefined> }
    await hooks["create.before"](shell)
    expect(shell.env.API_KEY).toBe("sk-abcdef123456789")
  })
})
