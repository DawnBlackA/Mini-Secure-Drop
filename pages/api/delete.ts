import type { NextApiRequest, NextApiResponse } from 'next'
import { basicInputFilter, rateLimit } from '@/lib/security'
import { getAuthToken, verifyJwt } from '@/lib/jwt'
import { removeCipher } from '@/lib/storage'
import { removeSharesByFile } from '@/lib/shares'

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!rateLimit(req, res)) return
  if (!basicInputFilter(req, res)) return
  if (req.method !== 'DELETE') {
    res.setHeader('Allow', 'DELETE')
    return res.status(405).json({ error: 'Method not allowed' })
  }
  const token = getAuthToken(req)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const payload = verifyJwt(token)
  if (!payload) return res.status(401).json({ error: 'Unauthorized' })
  const { id } = req.body || {}
  if (typeof id !== 'string' || id.length === 0) {
    return res.status(400).json({ error: 'Invalid payload' })
  }
  const ok = await removeCipher(payload.sub, id)
  if (!ok) return res.status(404).json({ error: 'Not found' })
  await removeSharesByFile(payload.sub, id)
  return res.status(200).json({ success: true })
}
