import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

type UserRecord = {
  id: string
  username: string
  salt: string // base64
  hash: string // base64
  iterations: number
}

const ROOT = path.resolve(process.cwd(), 'storage')
const USERS_FILE = path.join(ROOT, 'users.json')
const usersByName: Map<string, UserRecord> = new Map()
let loaded = false

function ensureStorageSync() {
  try {
    fs.mkdirSync(ROOT, { recursive: true })
  } catch {}
}

function loadUsersSync() {
  if (loaded) return
  ensureStorageSync()
  try {
    if (fs.existsSync(USERS_FILE)) {
      const raw = fs.readFileSync(USERS_FILE, 'utf8')
      const arr = JSON.parse(raw) as UserRecord[]
      usersByName.clear()
      for (const u of arr) usersByName.set(u.username, u)
    }
  } catch {
    // ignore parse errors, start fresh
  } finally {
    loaded = true
  }
}

function saveUsersSync() {
  ensureStorageSync()
  const arr = Array.from(usersByName.values())
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(arr, null, 2), 'utf8')
  } catch {}
}

function pbkdf2(password: string, salt: Buffer, iterations: number): Buffer {
  return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256')
}

export function getUserId(username: string): string | null {
  loadUsersSync()
  const rec = usersByName.get(username)
  return rec?.id || null
}

export function registerUser(username: string, password: string): { id: string } | { error: string } {
  loadUsersSync()
  const uname = username.trim()
  if (!/^[a-zA-Z0-9_\-]{3,32}$/.test(uname)) return { error: 'Invalid username' }
  if (password.length < 6) return { error: 'Password too short' }
  if (usersByName.has(uname)) return { error: 'User exists' }
  const id = 'u_' + crypto.randomBytes(8).toString('hex')
  const salt = crypto.randomBytes(16)
  const iterations = 120_000
  const hash = pbkdf2(password, salt, iterations)
  usersByName.set(uname, {
    id,
    username: uname,
    salt: salt.toString('base64'),
    hash: hash.toString('base64'),
    iterations,
  })
  saveUsersSync()
  return { id }
}

export function verifyUser(username: string, password: string): { id: string } | { error: string } {
  loadUsersSync()
  const rec = usersByName.get(username)
  if (!rec) return { error: 'Invalid credentials' }
  const salt = Buffer.from(rec.salt, 'base64')
  const hash = pbkdf2(password, salt, rec.iterations)
  const ok = crypto.timingSafeEqual(hash, Buffer.from(rec.hash, 'base64'))
  if (!ok) return { error: 'Invalid credentials' }
  return { id: rec.id }
}
