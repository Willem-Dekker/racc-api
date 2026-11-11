// Client IP resolution.
//
// Client-supplied headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are only
// believed when they were set by a proxy we trust, otherwise anyone can rotate them
// to dodge the rate limit. The expected chain in production is:
//
//   client -> Cloudflare edge -> cloudflared -> Traefik -> racc-api
//
// - The TCP peer of racc-api is Traefik.
// - Traefik has no forwardedHeaders.trustedIPs, so it deletes any incoming X-Real-Ip
//   and sets it to *its* TCP peer: cloudflared for tunnel traffic, or a Swarm ingress
//   address for anything that reached port 443 directly.
// - Cloudflare's edge overwrites CF-Connecting-IP, so it is trustworthy only when the
//   request really came through cloudflared.
//
// So: CF-Connecting-IP is used only when both the TCP peer and X-Real-Ip are in
// TRUSTED_PROXIES. X-Real-Ip is used when only the TCP peer is trusted. Otherwise the
// TCP peer itself is the client. TRUSTED_PROXIES is a comma-separated list of IPv4
// CIDRs or exact addresses; when unset, no header is trusted.

type PeerResolver = (request: Request) => string | null | undefined;

let peerResolver: PeerResolver = () => null;

export function setPeerResolver(resolver: PeerResolver): void {
  peerResolver = resolver;
}

function peerAddress(request: Request): string | null {
  try {
    return peerResolver(request) ?? null;
  } catch {
    return null;
  }
}

function normalizeIP(ip: string | null): string | null {
  if (!ip) return null;
  const trimmed = ip.trim();
  if (!trimmed) return null;
  // IPv4-mapped IPv6, as Bun reports IPv4 peers on a dual-stack socket
  return trimmed.toLowerCase().startsWith("::ffff:") && trimmed.includes(".")
    ? trimmed.slice(7)
    : trimmed;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    n = n * 256 + octet;
  }
  return n;
}

type Matcher = (ip: string) => boolean;

export function parseTrustedProxies(spec: string | undefined): Matcher[] {
  if (!spec) return [];
  const matchers: Matcher[] = [];
  for (const raw of spec.split(",")) {
    const entry = raw.trim();
    if (!entry) continue;
    const [addr, bitsRaw] = entry.split("/");
    const base = ipv4ToInt(addr);
    if (base === null) {
      // non-IPv4 entry: exact string match only
      matchers.push((ip) => ip === entry);
      continue;
    }
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) {
      throw new Error(`Invalid TRUSTED_PROXIES entry: ${entry}`);
    }
    const size = 2 ** (32 - bits);
    const network = Math.floor(base / size) * size;
    matchers.push((ip) => {
      const n = ipv4ToInt(ip);
      return n !== null && n >= network && n < network + size;
    });
  }
  return matchers;
}

const trustedProxies = parseTrustedProxies(process.env.TRUSTED_PROXIES);

function isTrusted(ip: string | null, matchers: Matcher[]): boolean {
  return ip !== null && matchers.some((m) => m(ip));
}

export function resolveClientIP(
  request: Request,
  rawPeer: string | null,
  matchers: Matcher[] = trustedProxies
): string | null {
  const peer = normalizeIP(rawPeer);
  if (!isTrusted(peer, matchers)) return peer;

  const proxyPeer = normalizeIP(request.headers.get("X-Real-IP"));
  if (!isTrusted(proxyPeer, matchers)) return proxyPeer ?? peer;

  return normalizeIP(request.headers.get("CF-Connecting-IP")) ?? proxyPeer;
}

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

class RateLimiter {
  private requests = new Map<string, RateLimitEntry>();
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private lastCleanup: number = 0;
  private readonly cleanupInterval: number = 60000;

  constructor(maxRequests: number, windowMs: number) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  private getClientIP(request: Request): string {
    const ip = resolveClientIP(request, peerAddress(request));

    // we want to generate a unique identifier for unknown users
    // to avoid it being used as a rate limit bypass
    if (!ip) {
      const userAgent = request.headers.get("User-Agent") || "";
      const acceptLanguage = request.headers.get("Accept-Language") || "";
      const acceptEncoding = request.headers.get("Accept-Encoding") || "";

      const fingerprint = `${userAgent}-${acceptLanguage}-${acceptEncoding}`;
      return `unknown-${this.simpleHash(fingerprint)}`;
    }

    return ip;
  }

  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  }

  // run the cleanup every minute to be more proactive,
  // this avoids a memory leak when expired entries aren't
  // cleaned up and remain in memory indefinitely.
  // i also added a hard limit so it'll automatically
  // trim the fat if too many entries are logged

  private cleanupExpiredEntries(): void {
    const now = Date.now();

    if (now - this.lastCleanup < this.cleanupInterval) {
      return;
    }

    this.lastCleanup = now;

    for (const [key, entry] of this.requests.entries()) {
      if (now > entry.resetTime) {
        this.requests.delete(key);
      }
    }

    if (this.requests.size > 10000) {
      const sortedEntries = Array.from(this.requests.entries()).sort(
        ([, a], [, b]) => a.resetTime - b.resetTime
      );

      const toKeep = sortedEntries.slice(-5000);
      this.requests.clear();

      for (const [key, entry] of toKeep) {
        this.requests.set(key, entry);
      }
    }
  }

  checkRateLimit(request: Request): {
    allowed: boolean;
    remaining: number;
    resetTime: number;
  } {
    const clientIP = this.getClientIP(request);
    const now = Date.now();

    this.cleanupExpiredEntries();

    const entry = this.requests.get(clientIP);

    if (!entry || now > entry.resetTime) {
      const resetTime = now + this.windowMs;
      this.requests.set(clientIP, { count: 1, resetTime });
      return {
        allowed: true,
        remaining: this.maxRequests - 1,
        resetTime,
      };
    }

    if (entry.count >= this.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: entry.resetTime,
      };
    }

    entry.count++;
    return {
      allowed: true,
      remaining: this.maxRequests - entry.count,
      resetTime: entry.resetTime,
    };
  }
}

export const photoRateLimiter = new RateLimiter(10, 20 * 1000);
