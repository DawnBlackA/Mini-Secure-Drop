import type { NextApiRequest, NextApiResponse } from 'next'
import { basicInputFilter, rateLimit } from '@/lib/security'
import { getAuthToken, verifyJwt } from '@/lib/jwt'
import { createShare, listIncomingShares, listOutgoingShares } from '@/lib/shares'
import { getUser, getUserById } from '@/lib/users'
import { listCiphers } from '@/lib/storage'

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '30mb',
    },
  },
}

function b64ToBuffer(data: string): Buffer {
  try {
    return Buffer.from(data, 'base64')
  } catch {
    return Buffer.alloc(0)
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!rateLimit(req, res)) return
  if (!basicInputFilter(req, res)) return
  const token = getAuthToken(req)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const payload = verifyJwt(token)
  if (!payload) return res.status(401).json({ error: 'Unauthorized' })

  if (req.method === 'GET') {
    const { direction } = req.query
    const dir = Array.isArray(direction) ? direction[0] : direction || 'incoming'
    if (dir !== 'incoming' && dir !== 'outgoing') {
      return res.status(400).json({ error: 'Invalid direction' })
    }
    const list = dir === 'incoming'
      ? await listIncomingShares(payload.sub)
      : await listOutgoingShares(payload.sub)
    return res.status(200).json(list)
  }

  if (req.method === 'POST') {
    const { fileId, targetUsername, encryptedKey, iv, cipher, size } = req.body || {}
    if (typeof fileId !== 'string' || typeof targetUsername !== 'string' || typeof encryptedKey !== 'string' || typeof iv !== 'string' || typeof cipher !== 'string') {
      return res.status(400).json({ error: 'Invalid payload' })
    }
    const payloadSize = typeof size === 'number' && Number.isFinite(size) ? size : null
    const encKeyBuf = b64ToBuffer(encryptedKey)
    const ivBuf = b64ToBuffer(iv)
    const cipherBuf = b64ToBuffer(cipher)
    if (encKeyBuf.length === 0 || ivBuf.length === 0 || cipherBuf.length === 0) {
      return res.status(400).json({ error: 'Invalid encoding' })
    }
    const MAX_SHARE_BYTES = 20 * 1024 * 1024
    if (cipherBuf.length > MAX_SHARE_BYTES) {
      return res.status(413).json({ error: 'Shared payload too large' })
    }
    const target = getUser(targetUsername)
    if (!target || !target.publicKey) {
      return res.status(404).json({ error: 'Target user not found' })
    }
    const owner = getUserById(payload.sub)
    if (!owner) {
      return res.status(400).json({ error: 'Owner not found' })
    }
    const files = await listCiphers(payload.sub)
    const meta = files.find((f) => f.id === fileId)
    if (!meta) {
      return res.status(404).json({ error: 'File not found' })
    }
    const stored = await createShare({
      ownerId: payload.sub,
      ownerUsername: owner.username,
      targetId: target.id,
      targetUsername: target.username,
      fileId,
      originalName: meta.originalName,
      size: payloadSize ?? meta.size,
      encryptedKey: encKeyBuf,
      iv: ivBuf,
      cipher: cipherBuf,
    })
    return res.status(201).json(stored)
  }

  res.setHeader('Allow', 'GET, POST')
  return res.status(405).json({ error: 'Method not allowed' })
}
