import type { NextApiRequest, NextApiResponse } from 'next'
import { basicInputFilter, rateLimit } from '@/lib/security'
import { getUser } from '@/lib/users'

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!rateLimit(req, res)) return
  if (!basicInputFilter(req, res)) return
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET')
    return res.status(405).json({ error: 'Method not allowed' })
  }
  const { username } = req.query
  const uname = Array.isArray(username) ? username[0] : username
  if (!uname || typeof uname !== 'string') {
    return res.status(400).json({ error: 'Missing username' })
  }
  const user = getUser(uname)
  if (!user || !user.publicKey) {
    return res.status(404).json({ error: 'Public key not found' })
  }
  return res.status(200).json({ username: user.username, publicKey: user.publicKey })
}
