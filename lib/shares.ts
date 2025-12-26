import crypto from 'crypto'
import fsp from 'fs/promises'
import path from 'path'

const ROOT = path.resolve(process.cwd(), 'storage')
const SHARES_DIR = path.join(ROOT, 'shares')

export type ShareMeta = {
  id: string
  ownerId: string
  ownerUsername: string
  targetId: string
  targetUsername: string
  fileId: string
  originalName: string
  size: number
  createdAt: string
}

type SharePayload = {
  meta: ShareMeta
  encryptedKey: Buffer
  iv: Buffer
  cipher: Buffer
}

async function ensureSharesDir() {
  await fsp.mkdir(SHARES_DIR, { recursive: true })
}

function shareBase(id: string): string {
  return path.join(SHARES_DIR, id)
}

async function readMeta(id: string): Promise<ShareMeta | null> {
  try {
    const raw = await fsp.readFile(shareBase(id) + '.json', 'utf8')
    return JSON.parse(raw) as ShareMeta
  } catch (e: any) {
    if (e && e.code === 'ENOENT') return null
    throw e
  }
}

async function writeMeta(meta: ShareMeta) {
  await ensureSharesDir()
  await fsp.writeFile(shareBase(meta.id) + '.json', JSON.stringify(meta, null, 2), 'utf8')
}

async function writePayload(id: string, encryptedKey: Buffer, iv: Buffer, cipher: Buffer) {
  const header = Buffer.allocUnsafe(8)
  header.writeUInt32BE(encryptedKey.length, 0)
  header.writeUInt32BE(iv.length, 4)
  const buf = Buffer.concat([header, encryptedKey, iv, cipher])
  await fsp.writeFile(shareBase(id) + '.bin', buf)
}

async function readPayload(id: string): Promise<{ encryptedKey: Buffer; iv: Buffer; cipher: Buffer } | null> {
  try {
    const buf = await fsp.readFile(shareBase(id) + '.bin')
    if (buf.length < 8) return null
    const keyLen = buf.readUInt32BE(0)
    const ivLen = buf.readUInt32BE(4)
    const offset = 8
    if (keyLen < 1 || ivLen < 1) return null
    const ivStart = offset + keyLen
    const cipherStart = ivStart + ivLen
    if (buf.length < cipherStart) return null
    const encryptedKey = buf.slice(offset, offset + keyLen)
    const iv = buf.slice(ivStart, ivStart + ivLen)
    const cipher = buf.slice(cipherStart)
    if (cipher.length === 0) return null
    return { encryptedKey, iv, cipher }
  } catch (e: any) {
    if (e && e.code === 'ENOENT') return null
    throw e
  }
}

async function listAllMetas(): Promise<ShareMeta[]> {
  await ensureSharesDir()
  const entries = await fsp.readdir(SHARES_DIR)
  const metas: ShareMeta[] = []
  for (const entry of entries) {
    if (!entry.endsWith('.json')) continue
    const id = entry.slice(0, -5)
    const meta = await readMeta(id)
    if (meta) metas.push(meta)
  }
  metas.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  return metas
}

export async function createShare(options: {
  ownerId: string
  ownerUsername: string
  targetId: string
  targetUsername: string
  fileId: string
  originalName: string
  size: number
  encryptedKey: Buffer
  iv: Buffer
  cipher: Buffer
}): Promise<ShareMeta> {
  await ensureSharesDir()
  const id = 's_' + crypto.randomBytes(8).toString('hex')
  const createdAt = new Date().toISOString()
  const meta: ShareMeta = {
    id,
    ownerId: options.ownerId,
    ownerUsername: options.ownerUsername,
    targetId: options.targetId,
    targetUsername: options.targetUsername,
    fileId: options.fileId,
    originalName: options.originalName,
    size: options.size,
    createdAt,
  }
  await writeMeta(meta)
  await writePayload(id, options.encryptedKey, options.iv, options.cipher)
  return meta
}

export async function listIncomingShares(userId: string): Promise<ShareMeta[]> {
  const metas = await listAllMetas()
  return metas.filter((m) => m.targetId === userId)
}

export async function listOutgoingShares(ownerId: string): Promise<ShareMeta[]> {
  const metas = await listAllMetas()
  return metas.filter((m) => m.ownerId === ownerId)
}

export async function readShareForUser(userId: string, shareId: string): Promise<SharePayload | null> {
  const meta = await readMeta(shareId)
  if (!meta) return null
  if (meta.targetId !== userId && meta.ownerId !== userId) return null
  const payload = await readPayload(shareId)
  if (!payload) return null
  return { meta, ...payload }
}

export async function removeSharesByFile(ownerId: string, fileId: string): Promise<number> {
  const metas = await listAllMetas()
  const doomed = metas.filter((m) => m.ownerId === ownerId && m.fileId === fileId)
  let count = 0
  for (const meta of doomed) {
    await Promise.all([
      fsp.unlink(shareBase(meta.id) + '.json').catch(() => {}),
      fsp.unlink(shareBase(meta.id) + '.bin').catch(() => {}),
    ])
    count += 1
  }
  return count
}
