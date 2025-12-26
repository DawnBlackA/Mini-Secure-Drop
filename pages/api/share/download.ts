import type { NextApiRequest, NextApiResponse } from 'next'
import { basicInputFilter, rateLimit } from '@/lib/security'
import { getAuthToken, verifyJwt } from '@/lib/jwt'
import { readShareForUser } from '@/lib/shares'

function toBase64(buf: Buffer): string {
  return buf.toString('base64')
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!rateLimit(req, res)) return
  if (!basicInputFilter(req, res)) return
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET')
    return res.status(405).json({ error: 'Method not allowed' })
  }
  const token = getAuthToken(req)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const payload = verifyJwt(token)
  if (!payload) return res.status(401).json({ error: 'Unauthorized' })

  const { id } = req.query
  const shareId = Array.isArray(id) ? id[0] : id
  if (!shareId || typeof shareId !== 'string') {
    return res.status(400).json({ error: 'Missing id' })
  }
  const found = await readShareForUser(payload.sub, shareId)
  if (!found) {
    return res.status(404).json({ error: 'Not found' })
  }
  return res.status(200).json({
    id: found.meta.id,
    ownerUsername: found.meta.ownerUsername,
    originalName: found.meta.originalName,
    size: found.meta.size,
    createdAt: found.meta.createdAt,
    encryptedKey: toBase64(found.encryptedKey),
    iv: toBase64(found.iv),
    cipher: toBase64(found.cipher),
  })
}
