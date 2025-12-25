import type { NextApiRequest, NextApiResponse } from 'next'
import { basicInputFilter, rateLimit } from '@/lib/security'
import { getAuthToken, verifyJwt } from '@/lib/jwt'
import { readCipher } from '@/lib/storage'

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
  const fid = Array.isArray(id) ? id[0] : id
  if (!fid || typeof fid !== 'string') return res.status(400).json({ error: 'Missing id' })

  const found = await readCipher(payload.sub, fid)
  if (!found) return res.status(404).json({ error: 'Not found' })

  res.setHeader('Content-Type', 'application/octet-stream')
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(found.meta.originalName)}"`)
  res.status(200).send(found.data)
}
