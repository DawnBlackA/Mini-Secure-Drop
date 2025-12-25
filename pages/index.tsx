import { useEffect, useMemo, useState } from 'react'

type FileMeta = {
  id: string
  owner: string
  originalName: string
  size: number
  createdAt: string
}

const ITERATIONS = 120_000
const SALT_LEN = 16
const IV_LEN = 12

function useLocalStorage(key: string) {
  const [value, setValue] = useState<string | null>(null)
  useEffect(() => {
    try {
      const v = localStorage.getItem(key)
      setValue(v)
    } catch {}
  }, [key])
  const save = (v: string | null) => {
    try {
      if (v === null) localStorage.removeItem(key)
      else localStorage.setItem(key, v)
      setValue(v)
    } catch {}
  }
  return [value, save] as const
}

async function deriveAesGcmKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

async function encryptFile(file: File, password: string): Promise<{ payload: Uint8Array; originalName: string }>
{
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN))
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN))
  const key = await deriveAesGcmKey(password, salt)
  const buf = await file.arrayBuffer()
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf))
  const payload = new Uint8Array(SALT_LEN + IV_LEN + cipher.byteLength)
  payload.set(salt, 0)
  payload.set(iv, SALT_LEN)
  payload.set(cipher, SALT_LEN + IV_LEN)
  return { payload, originalName: file.name || 'cipher.bin' }
}

async function decryptToBlob(data: ArrayBuffer, password: string, fallbackName = 'file.bin'): Promise<{ blob: Blob; name: string }>
{
  const u8 = new Uint8Array(data)
  if (u8.byteLength < SALT_LEN + IV_LEN + 16) throw new Error('密文格式不正确')
  const salt = u8.slice(0, SALT_LEN)
  const iv = u8.slice(SALT_LEN, SALT_LEN + IV_LEN)
  const cipher = u8.slice(SALT_LEN + IV_LEN)
  const key = await deriveAesGcmKey(password, salt)
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher).catch(() => { throw new Error('解密失败，口令可能不正确') })
  return { blob: new Blob([plain]), name: fallbackName }
}

export default function IndexPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useLocalStorage('msd_token')
  const [sessionUser, setSessionUser] = useLocalStorage('msd_user')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [files, setFiles] = useState<FileMeta[]>([])
  const authed = !!token

  const headers = useMemo(() => (token ? { Authorization: `Bearer ${token}` } : {}), [token])

  const register = async () => {
    setBusy(true); setMessage(null)
    try {
      const r = await fetch('/api/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || '注册失败')
      setToken(j.token)
      setSessionUser(j.username)
      setMessage('注册成功')
    } catch (e: any) {
      setMessage(e.message || '注册失败')
    } finally { setBusy(false) }
  }

  const login = async () => {
    setBusy(true); setMessage(null)
    try {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) })
      const j = await r.json()
      if (!r.ok) throw new Error(j.error || '登录失败')
      setToken(j.token)
      setSessionUser(j.username)
      setMessage('登录成功')
    } catch (e: any) {
      setMessage(e.message || '登录失败')
    } finally { setBusy(false) }
  }

  const logout = () => { setToken(null); setSessionUser(null); setFiles([]); setMessage('已退出'); }

  const refresh = async () => {
    if (!authed) return
    const r = await fetch('/api/list', { headers })
    if (r.ok) {
      const j: FileMeta[] = await r.json()
      setFiles(j)
    }
  }

  useEffect(() => { if (authed) { refresh() } }, [authed])

  const onUpload = async (ev: React.ChangeEvent<HTMLInputElement>) => {
    const f = ev.target.files?.[0]
    if (!f) return
    if (!authed) { setMessage('请先登录'); return }
    if (!password) { setMessage('请输入用于加解密的口令'); return }
    setBusy(true); setMessage('正在本地加密并上传…')
    try {
      const { payload, originalName } = await encryptFile(f, password)
      const r = await fetch('/api/upload', {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/octet-stream', 'X-File-Name': originalName },
        body: payload,
      })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(j.error || '上传失败')
      setMessage('上传成功')
      await refresh()
      ev.target.value = ''
    } catch (e: any) {
      setMessage(e.message || '上传失败')
    } finally { setBusy(false) }
  }

  const onDownload = async (m: FileMeta) => {
    if (!authed) { setMessage('请先登录'); return }
    if (!password) { setMessage('请输入用于加解密的口令'); return }
    setBusy(true); setMessage('正在下载并本地解密…')
    try {
      const r = await fetch(`/api/download?id=${encodeURIComponent(m.id)}`, { headers })
      if (!r.ok) throw new Error('下载失败')
      const buf = await r.arrayBuffer()
      const { blob, name } = await decryptToBlob(buf, password, m.originalName)
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = name
      document.body.appendChild(a)
      a.click()
      a.remove()
      setMessage('解密完成')
    } catch (e: any) {
      setMessage(e.message || '解密失败')
    } finally { setBusy(false) }
  }

  return (
    <div className="max-w-3xl mx-auto p-6 space-y-6">
      <h1 className="text-2xl font-semibold">MiniSecureDrop</h1>
      <p className="text-sm text-gray-500">端到端加密文件共享（AES-GCM 256 + PBKDF2 120k）</p>

      <section className="border rounded p-4 space-y-2">
        <h2 className="font-medium">功能要点</h2>
        <ul className="list-disc pl-6 text-sm text-gray-700 space-y-1">
          <li>本地加密/解密，服务端不接触明文</li>
          <li>JWT 鉴权与按所有者前缀隔离存储</li>
          <li>入侵防护：IP 速率限制 + 恶意模式拦截（SQLi/XSS）</li>
          <li>重启后仍可登录并查看历史上传（用户持久化）</li>
        </ul>
      </section>

      <section className="border rounded p-4 space-y-3">
        <h2 className="font-medium">账号与会话</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input className="border rounded px-3 py-2" placeholder="用户名" value={username} onChange={(e) => setUsername(e.target.value)} />
          <input className="border rounded px-3 py-2" placeholder="口令（用于登录与加解密）" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <div className="flex gap-2">
            <button className="px-3 py-2 rounded bg-blue-600 text-white disabled:opacity-50" disabled={busy} onClick={register}>注册</button>
            <button className="px-3 py-2 rounded bg-green-600 text-white disabled:opacity-50" disabled={busy} onClick={login}>登录</button>
            <button className="px-3 py-2 rounded bg-gray-200" onClick={logout}>退出</button>
          </div>
        </div>
        <div className="text-sm text-gray-600">当前用户：{sessionUser || '未登录'}</div>
      </section>

      <section className="border rounded p-4 space-y-3">
        <h2 className="font-medium">上传（本地加密后再发送）</h2>
        <input type="file" onChange={onUpload} />
        <div className="text-xs text-gray-500">加密格式：[16字节salt | 12字节IV | AES-GCM密文]</div>
      </section>

      <section className="border rounded p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-medium">我的文件</h2>
          <button className="px-3 py-2 rounded bg-gray-100" onClick={refresh}>刷新</button>
        </div>
        <ul className="divide-y">
          {files.map((m) => (
            <li key={m.id} className="py-2 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="font-mono text-sm truncate">{m.originalName}</div>
                <div className="text-xs text-gray-500">{new Date(m.createdAt).toLocaleString()} · {m.size} B</div>
              </div>
              <div className="shrink-0 flex gap-2">
                <button className="px-3 py-1 rounded bg-indigo-600 text-white disabled:opacity-50" disabled={busy} onClick={() => onDownload(m)}>下载并解密</button>
              </div>
            </li>
          ))}
          {files.length === 0 && <li className="py-4 text-sm text-gray-500">暂无文件</li>}
        </ul>
      </section>

      <section className="border rounded p-4 space-y-3">
        <h2 className="font-medium">入侵防护测试</h2>
        <p className="text-sm text-gray-600">演示以下两种防护：恶意输入拦截（SQLi/XSS 特征），以及 IP 速率限制（10 秒内超过 30 次返回 429）。</p>
        <div className="flex flex-wrap gap-2">
          <button
            className="px-3 py-2 rounded bg-red-600 text-white disabled:opacity-50"
            disabled={busy}
            onClick={async () => {
              setBusy(true); setMessage('正在测试恶意输入拦截…')
              try {
                const body = { username: '<script>alert(1)</script>', password: 'secret123' }
                const r = await fetch('/api/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
                const j = await r.json().catch(() => ({}))
                if (r.status === 400) setMessage('已拦截恶意输入（HTTP 400）')
                else setMessage(`状态码 ${r.status}：${j.error || '未触发拦截'}`)
              } catch (e: any) {
                setMessage(e.message || '测试失败')
              } finally { setBusy(false) }
            }}
          >
            测试恶意输入拦截
          </button>
          <button
            className="px-3 py-2 rounded bg-orange-600 text-white disabled:opacity-50"
            disabled={busy}
            onClick={async () => {
              setBusy(true); setMessage('正在测试速率限制（发送 35 次请求）…')
              try {
                const endpoint = authed ? '/api/list' : '/api/login'
                const init = authed
                  ? { method: 'GET', headers }
                  : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'dummy', password: 'dummy' }) }
                const reqs = Array.from({ length: 35 }, () => fetch(endpoint, init as any).then((res) => res.status).catch(() => -1))
                const statuses = await Promise.all(reqs)
                const c429 = statuses.filter((s) => s === 429).length
                const cOk = statuses.filter((s) => s >= 200 && s < 300).length
                setMessage(`完成：${statuses.length} 次；429：${c429} 次；2xx：${cOk} 次。若 429>0，说明速率限制生效。`)
              } catch (e: any) {
                setMessage(e.message || '测试失败')
              } finally { setBusy(false) }
            }}
          >
            测试 IP 速率限制
          </button>
        </div>
      </section>

      {message && <div className="p-3 rounded bg-yellow-50 text-yellow-800 text-sm">{message}</div>}
    </div>
  )
}
