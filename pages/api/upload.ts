import type { NextApiRequest, NextApiResponse } from 'next'
import { rateLimit } from '@/lib/security'
import { getAuthToken, verifyJwt } from '@/lib/jwt'
import { saveCipher } from '@/lib/storage'

export const config = {
  api: {
    bodyParser: false,
  },
}

function resolveOriginalName(header: string | string[] | undefined): string {
  if (!header) return 'cipher.bin'
  const value = Array.isArray(header) ? header[0] : header
  if (!value) return 'cipher.bin'
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!rateLimit(req, res)) return
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ error: 'Method not allowed' })
  }
  const token = getAuthToken(req)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const payload = verifyJwt(token)
  if (!payload) return res.status(401).json({ error: 'Unauthorized' })

  const chunks: Buffer[] = []
  await new Promise<void>((resolve, reject) => {
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve())
    req.on('error', reject)
  })
  const buf = Buffer.concat(chunks)
  if (buf.length === 0) return res.status(400).json({ error: 'Empty body' })
  // Optional basic size cap: 20MB for demo
  const MAX = 20 * 1024 * 1024
  if (buf.length > MAX) return res.status(413).json({ error: 'Payload too large' })

  const originalName = resolveOriginalName(req.headers['x-file-name'])
  try {
    const meta = await saveCipher(payload.sub, originalName, buf)
    return res.status(200).json({ id: meta.id, originalName: meta.originalName, size: meta.size, createdAt: meta.createdAt })
  } catch (e: any) {
    return res.status(500).json({ error: 'Failed to save file' })
  }
}
