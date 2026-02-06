import { readdir, readFile, stat } from "fs/promises"
import { join, basename } from "path"

// ═══════════════════════════════════════════════════════════════
// Scans directory for .env* files up to specified depth
// Returns array of absolute file paths
// ═══════════════════════════════════════════════════════════════
export async function scanEnvFiles(dir: string, maxDepth: number): Promise<string[]> {
  const envFiles: string[] = []
  
  async function scan(currentDir: string, depth: number) {
    if (depth > maxDepth) return
    
    try {
      const entries = await readdir(currentDir, { withFileTypes: true })
      
      for (const entry of entries) {
        const fullPath = join(currentDir, entry.name)
        
        if (entry.isFile() && isEnvFile(entry.name)) {
          // Found .env* file
          envFiles.push(fullPath)
        } else if (entry.isDirectory() && !isIgnoredDir(entry.name)) {
          // Recurse into subdirectory
          await scan(fullPath, depth + 1)
        }
      }
    } catch {
      // Ignore permission errors, missing dirs, etc.
    }
  }
  
  await scan(dir, 0)
  return envFiles
}

// ═══════════════════════════════════════════════════════════════
// Checks if filename matches .env* pattern
// Matches: .env, .env.local, .env.development, .env.production, etc.
// ═══════════════════════════════════════════════════════════════
function isEnvFile(filename: string): boolean {
  // Match .env, .env.local, .env.production, etc.
  // Exclude .env.example - those are templates with placeholder values
  if (filename === ".env") return true
  if (filename.startsWith(".env.") && !filename.endsWith(".example")) return true
  return false
}

// ═══════════════════════════════════════════════════════════════
// Directories to skip (node_modules, .git, etc.)
// ═══════════════════════════════════════════════════════════════
function isIgnoredDir(dirname: string): boolean {
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
    "vendor",
  ]
  return ignored.includes(dirname) || dirname.startsWith(".")
}

// ═══════════════════════════════════════════════════════════════
// Parses .env file content into key-value pairs
// Handles: KEY=value, KEY="quoted value", KEY='single quoted'
// Ignores: comments (#), empty lines
// ═══════════════════════════════════════════════════════════════
export async function parseEnvFile(filePath: string): Promise<Record<string, string>> {
  const vars: Record<string, string> = {}
  
  try {
    const content = await readFile(filePath, "utf-8")
    const lines = content.split("\n")
    
    for (const line of lines) {
      const trimmed = line.trim()
      
      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith("#")) continue
      
      // Find first = sign
      const eqIndex = trimmed.indexOf("=")
      if (eqIndex === -1) continue
      
      const key = trimmed.slice(0, eqIndex).trim()
      let value = trimmed.slice(eqIndex + 1).trim()
      
      // Skip if key is empty or invalid
      if (!key || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue
      
      // Remove surrounding quotes if present
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1)
      }
      
      // Handle inline comments (only for unquoted values)
      if (!trimmed.slice(eqIndex + 1).trim().startsWith('"') &&
          !trimmed.slice(eqIndex + 1).trim().startsWith("'")) {
        const commentIndex = value.indexOf(" #")
        if (commentIndex !== -1) {
          value = value.slice(0, commentIndex).trim()
        }
      }
      
      vars[key] = value
    }
  } catch {
    // Ignore read errors
  }
  
  return vars
}
