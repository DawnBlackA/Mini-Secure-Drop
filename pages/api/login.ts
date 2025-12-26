import type { NextApiRequest, NextApiResponse } from 'next'
import { basicInputFilter, rateLimit } from '@/lib/security'
import { verifyUser } from '@/lib/users'
import { signJwt } from '@/lib/jwt'

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!rateLimit(req, res)) return
  if (!basicInputFilter(req, res)) return
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ error: 'Method not allowed' })
  }
  const { username, password } = req.body || {}
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid payload' })
  }
  const r = verifyUser(username, password)
  if ('error' in r) return res.status(401).json({ error: r.error })
  const token = signJwt({ sub: r.id, username })
  return res.status(200).json({ token, userId: r.id, username, publicKey: r.publicKey || null })
}
