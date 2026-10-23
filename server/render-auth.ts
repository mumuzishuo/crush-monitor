import { timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction } from "express";

const deployed = process.env.RENDER === "true";
const username = process.env.CRUSH_AUTH_USER || "";
const password = process.env.CRUSH_AUTH_PASSWORD || "";

if (deployed && (username.length < 3 || password.length < 18)) {
  throw new Error("Set CRUSH_AUTH_USER (3+ chars) and CRUSH_AUTH_PASSWORD (18+ chars) in Render Environment.");
}
const expected = Buffer.from(`${username}:${password}`, "utf8");
const failed = new Map<string, { count: number; since: number }>();

export function renderPasswordGate(req: Request, res: Response, next: NextFunction) {
  if (!deployed) return next();
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  let state = failed.get(ip);
  if (!state || now - state.since > 15 * 60_000) {
    state = { count: 0, since: now };
    failed.set(ip, state);
  }
  if (state.count >= 20) {
    res.setHeader("Retry-After", "900");
    res.status(429).send("Too many attempts. Try again later.");
    return;
  }
  const header = req.get("authorization") || "";
  let valid = false;
  if (header.startsWith("Basic ")) {
    const value = header.slice(6);
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length < 8192) {
      const received = Buffer.from(value, "base64");
      valid = received.length === expected.length && timingSafeEqual(received, expected);
    }
  }
  if (!valid) {
    state.count += 1;
    res.setHeader("WWW-Authenticate", 'Basic realm="Private Crush Monitor", charset="UTF-8"');
    res.setHeader("Cache-Control", "no-store");
    res.status(401).send("Authentication required");
    return;
  }
  failed.delete(ip);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Strict-Transport-Security", "max-age=31536000");
  next();
}
