import fs from 'fs'
import fsp from 'fs/promises'
import path from 'path'

const ROOT = path.resolve(process.cwd(), 'storage')

type Meta = {
  id: string
  owner: string
  originalName: string
  size: number
  createdAt: string
}

function normalizeOriginalName(name: string): string {
  const trimmed = (name || '').trim().slice(0, 200)
  if (!trimmed) return 'cipher.bin'
  // Block path separators and control chars to keep metadata safe while preserving locale-specific characters.
  return trimmed.replace(/[\0\r\n]/g, '').replace(/[\\/]/g, '_') || 'cipher.bin'
}

async function ensureDir(p: string) {
  await fsp.mkdir(p, { recursive: true })
}

export async function ensureStorage() {
  await ensureDir(ROOT)
}

function ownerDir(owner: string): string {
  return path.join(ROOT, owner)
}

export async function saveCipher(owner: string, originalName: string, data: Buffer): Promise<Meta> {
  await ensureStorage()
  const dir = ownerDir(owner)
  await ensureDir(dir)
  const rand = Math.random().toString(36).slice(2, 10) + Date.now().toString(36)
  const id = `${owner}__${rand}`
  const base = path.join(dir, id)
  const meta: Meta = {
    id,
    owner,
    originalName: normalizeOriginalName(originalName || 'cipher.bin'),
    size: data.length,
    createdAt: new Date().toISOString(),
  }
  await fsp.writeFile(base + '.bin', data)
  await fsp.writeFile(base + '.json', JSON.stringify(meta, null, 2), 'utf8')
  return meta
}

export async function listCiphers(owner: string): Promise<Meta[]> {
  const dir = ownerDir(owner)
  try {
    const entries = await fsp.readdir(dir)
    const metas = entries.filter((e) => e.endsWith('.json'))
    const out: Meta[] = []
    for (const m of metas) {
      const raw = await fsp.readFile(path.join(dir, m), 'utf8')
      out.push(JSON.parse(raw))
    }
    // newest first
    out.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    return out
  } catch (e: any) {
    if (e && (e.code === 'ENOENT' || e.code === 'ENOTDIR')) return []
    throw e
  }
}

export async function readCipher(owner: string, id: string): Promise<{ meta: Meta; data: Buffer } | null> {
  if (!id.startsWith(owner + '__')) return null
  const base = path.join(ownerDir(owner), id)
  try {
    const [metaRaw, bin] = await Promise.all([
      fsp.readFile(base + '.json', 'utf8'),
      fsp.readFile(base + '.bin'),
    ])
    return { meta: JSON.parse(metaRaw) as Meta, data: bin }
  } catch (e: any) {
    if (e && e.code === 'ENOENT') return null
    throw e
  }
}

export async function removeCipher(owner: string, id: string): Promise<boolean> {
  if (!id.startsWith(owner + '__')) return false
  const base = path.join(ownerDir(owner), id)
  try {
    await Promise.all([
      fsp.unlink(base + '.json').catch(() => {}),
      fsp.unlink(base + '.bin').catch(() => {}),
    ])
    return true
  } catch {
    return false
  }
}
