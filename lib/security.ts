import type { NextApiRequest, NextApiResponse } from 'next'

// Simple in-memory rate limiter: 30 requests per 10 seconds per IP
const WINDOW_MS = 10_000
const MAX_REQ = 30
const ipHits: Map<string, number[]> = new Map()

export function rateLimit(req: NextApiRequest, res: NextApiResponse): boolean {
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'
  const now = Date.now()
  const arr = ipHits.get(ip) || []
  const recent = arr.filter((t) => now - t <= WINDOW_MS)
  recent.push(now)
  ipHits.set(ip, recent)
  if (recent.length > MAX_REQ) {
    res.status(429).json({ error: 'Too many requests' })
    return false
  }
  return true
}

const MALICIOUS_PATTERNS: RegExp[] = [
  /union\s+select/i,
  /<script/i,
  /\bon\w+\s*=\s*/i, // onerror=, onclick=
  /\b1\s*=\s*1\b/i,
  /;\s*--/i,
  /drop\s+table/i,
  /insert\s+into/i,
  /update\s+\w+\s+set/i,
  /alert\s*\(/i,
]

function containsMalicious(str: string): boolean {
  return MALICIOUS_PATTERNS.some((re) => re.test(str))
}

export function basicInputFilter(req: NextApiRequest, res: NextApiResponse): boolean {
  try {
    // Check URL and query
    if (req.url && containsMalicious(req.url)) {
      res.status(400).json({ error: 'Bad request' })
      return false
    }
    for (const [k, v] of Object.entries(req.query)) {
      const s = Array.isArray(v) ? v.join(' ') : String(v)
      if (containsMalicious(k) || containsMalicious(s)) {
        res.status(400).json({ error: 'Bad request' })
        return false
      }
    }
    // Check JSON bodies only (skip raw binary handlers)
    if (req.headers['content-type']?.includes('application/json') && req.body) {
      const flat = typeof req.body === 'string' ? req.body : JSON.stringify(req.body)
      if (containsMalicious(flat)) {
        res.status(400).json({ error: 'Bad request' })
        return false
      }
    }
    return true
  } catch {
    res.status(400).json({ error: 'Bad request' })
    return false
  }
}
