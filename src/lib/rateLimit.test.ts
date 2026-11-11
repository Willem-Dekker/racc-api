import { describe, expect, test } from "bun:test";
import { parseTrustedProxies, resolveClientIP } from "./rateLimit";

const trusted = parseTrustedProxies("10.0.8.0/24");
const TRAEFIK = "10.0.8.5";
const CLOUDFLARED = "10.0.8.9";
const INGRESS = "10.0.0.2";

function req(headers: Record<string, string>): Request {
  return new Request("http://raccapi/raccoon", { headers });
}

describe("resolveClientIP", () => {
  test("tunnel traffic uses CF-Connecting-IP", () => {
    const r = req({ "X-Real-IP": CLOUDFLARED, "CF-Connecting-IP": "203.0.113.7" });
    expect(resolveClientIP(r, TRAEFIK, trusted)).toBe("203.0.113.7");
  });

  test("direct-to-Traefik traffic ignores a spoofed CF-Connecting-IP", () => {
    const r = req({ "X-Real-IP": INGRESS, "CF-Connecting-IP": "198.51.100.1" });
    expect(resolveClientIP(r, TRAEFIK, trusted)).toBe(INGRESS);
  });

  test("X-Forwarded-For is never used", () => {
    const r = req({ "X-Real-IP": INGRESS, "X-Forwarded-For": "198.51.100.2" });
    expect(resolveClientIP(r, TRAEFIK, trusted)).toBe(INGRESS);
  });

  test("untrusted peer ignores all headers", () => {
    const r = req({ "X-Real-IP": CLOUDFLARED, "CF-Connecting-IP": "198.51.100.3" });
    expect(resolveClientIP(r, "10.0.2.4", trusted)).toBe("10.0.2.4");
  });

  test("no TRUSTED_PROXIES means no header is trusted", () => {
    const r = req({ "X-Real-IP": CLOUDFLARED, "CF-Connecting-IP": "198.51.100.4" });
    expect(resolveClientIP(r, TRAEFIK, parseTrustedProxies(undefined))).toBe(TRAEFIK);
  });

  test("IPv4-mapped IPv6 peer is normalised", () => {
    const r = req({ "X-Real-IP": CLOUDFLARED, "CF-Connecting-IP": "203.0.113.8" });
    expect(resolveClientIP(r, `::ffff:${TRAEFIK}`, trusted)).toBe("203.0.113.8");
  });

  test("trusted chain without CF-Connecting-IP falls back to X-Real-IP", () => {
    const r = req({ "X-Real-IP": CLOUDFLARED });
    expect(resolveClientIP(r, TRAEFIK, trusted)).toBe(CLOUDFLARED);
  });

  test("missing peer returns null so the fingerprint fallback applies", () => {
    expect(resolveClientIP(req({ "CF-Connecting-IP": "198.51.100.5" }), null, trusted)).toBeNull();
  });
});

describe("parseTrustedProxies", () => {
  test("matches CIDR bounds and exact addresses", () => {
    const [cidr, exact] = parseTrustedProxies("10.0.8.0/24, 192.168.2.17");
    expect(cidr("10.0.8.0")).toBe(true);
    expect(cidr("10.0.8.255")).toBe(true);
    expect(cidr("10.0.9.0")).toBe(false);
    expect(exact("192.168.2.17")).toBe(true);
    expect(exact("192.168.2.18")).toBe(false);
  });

  test("rejects an invalid prefix length", () => {
    expect(() => parseTrustedProxies("10.0.8.0/33")).toThrow();
  });
});
