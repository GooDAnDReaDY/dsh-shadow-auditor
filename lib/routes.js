import { URL } from "node:url";
import { buildSessionBills, billsToMarkdown } from "./report.js";

export function sanitizeExportConfig(cfg) {
  if (!cfg || typeof cfg !== "object") return {};
  const copy = { ...cfg };
  if (Array.isArray(copy.sensitivePathPatterns)) {
    copy.sensitivePathPatterns = copy.sensitivePathPatterns.map(p =>
      typeof p === "string" && p.length > 50 ? p.slice(0, 50) + "..." : p
    );
  }
  return copy;
}

export function isLoopbackAddress(addr) {
  if (!addr || typeof addr !== "string") return false;
  const clean = addr.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return (
    clean === "localhost" ||
    clean === "127.0.0.1" ||
    clean === "::1" ||
    clean === "::ffff:127.0.0.1" ||
    clean.startsWith("127.")
  );
}

export function extractBearerToken(authHeader) {
  if (typeof authHeader !== "string") return null;
  const match = authHeader.match(/^Bearer\s+(\S+)$/i);
  return match ? match[1].trim() : null;
}

export function extractTokenFromCookie(cookieHeader) {
  if (typeof cookieHeader !== "string") return null;
  const match = cookieHeader.match(/(?:^|;\s*)(?:dsh_token|token)=([^;]+)/);
  return match ? decodeURIComponent(match[1].trim()) : null;
}

export function isTrustedRequest(req, options = {}) {
  if (!req || !req.headers) return false;
  const headers = req.headers;

  const site = headers["sec-fetch-site"];
  if (site === "cross-site" || site === "same-site") {
    return false;
  }

  const host = headers.host || "";
  const origin = headers.origin;
  if (origin !== undefined) {
    if (origin === "null" || !origin) return false;
    try {
      const parsed = new URL(origin);
      if (parsed.host && host && parsed.host !== host) return false;
    } catch {
      return false;
    }
  }

  const referer = headers.referer;
  if (referer !== undefined && referer) {
    try {
      const parsed = new URL(referer);
      if (parsed.host && host && parsed.host !== host) return false;
    } catch {
      return false;
    }
  }

  const remote = req.socket?.remoteAddress || req.connection?.remoteAddress || "";
  const isLoopback = isLoopbackAddress(remote);

  const expectedToken =
    options.expectedToken !== undefined
      ? options.expectedToken
      : process.env.DSH_AUTH_TOKEN || process.env.DSH_TOKEN || options.serverToken || null;

  const bearer = extractBearerToken(headers.authorization);
  const cookieToken = extractTokenFromCookie(headers.cookie);
  const providedToken = bearer || cookieToken;

  if (providedToken) {
    if (!expectedToken || providedToken !== expectedToken) {
      return false;
    }
    return true;
  }

  if (site === "same-origin" && isLoopback) {
    return true;
  }

  return false;
}

export function registerHttpRoutes(ctx, deps = {}) {
  const { logger = console, recorder, getConfig, getLastAudit } = deps;
  if (!ctx || !ctx.webServer || typeof ctx.webServer.register !== "function") {
    return;
  }

  try {
    ctx.effect(
      () =>
        ctx.webServer.register({
          kind: "exact",
          path: "/dsh-shadow-auditor/audit",
          handler: (req, res) => {
            if (req.method !== "GET" && req.method !== "HEAD") {
              res.writeHead(405, {
                allow: "GET, HEAD",
                "content-type": "application/json; charset=utf-8",
              });
              res.end(JSON.stringify({ error: "Method Not Allowed" }));
              return;
            }
            const srvToken =
              ctx?.webServer?.token || process.env.DSH_AUTH_TOKEN || process.env.DSH_TOKEN;
            if (!isTrustedRequest(req, { expectedToken: srvToken })) {
              res.writeHead(403, { "content-type": "application/json; charset=utf-8" });
              res.end(JSON.stringify({ error: "Access denied: untrusted caller" }));
              return;
            }
            res.setHeader("content-type", "application/json");
            res.setHeader("cache-control", "no-store");
            const auditState = getLastAudit ? getLastAudit() : {};
            const stats = recorder?.getStats ? recorder.getStats() : {};
            const cfg = getConfig ? getConfig() : {};
            res.end(
              JSON.stringify({
                ...auditState,
                stats,
                config: sanitizeExportConfig(cfg),
              })
            );
          },
        }),
      "shadow-auditor: audit route"
    );

    ctx.effect(
      () =>
        ctx.webServer.register({
          kind: "exact",
          path: "/dsh-shadow-auditor/events",
          handler: async (req, res) => {
            if (req.method !== "GET" && req.method !== "HEAD") {
              res.writeHead(405, {
                allow: "GET, HEAD",
                "content-type": "application/json; charset=utf-8",
              });
              res.end(JSON.stringify({ error: "Method Not Allowed" }));
              return;
            }
            const srvToken =
              ctx?.webServer?.token || process.env.DSH_AUTH_TOKEN || process.env.DSH_TOKEN;
            if (!isTrustedRequest(req, { expectedToken: srvToken })) {
              res.writeHead(403, { "content-type": "application/json; charset=utf-8" });
              res.end(JSON.stringify({ error: "Access denied: untrusted caller" }));
              return;
            }
            try {
              res.setHeader("content-type", "application/json");
              res.setHeader("cache-control", "no-store");
              const url = new URL(req.url || "", "http://localhost");
              const rawLimit = parseInt(url.searchParams.get("limit") || "50", 10);
              const limit = Math.min(Math.max(1, Number.isFinite(rawLimit) ? rawLimit : 50), 200);
              const filter = url.searchParams.get("filter") || "all";
              const sid = url.searchParams.get("sessionId");

              let records = recorder?.readRecent ? await recorder.readRecent(limit * 3) : [];
              if (sid) {
                records = records.filter(r => r.sessionId === sid);
              }
              if (filter === "guard") {
                records = records.filter(
                  r => r.blockedByGuard !== undefined || (r.tags && r.tags.includes("command-safety"))
                );
              } else if (filter === "diff_gate") {
                records = records.filter(
                  r =>
                    (r.blockedByGuard && r.blockedByGuard.includes("DiffGate")) ||
                    (r.tags &&
                      (r.tags.includes("secret") ||
                        r.tags.includes("insecure_code") ||
                        r.tags.includes("prompt_injection")))
                );
              } else if (filter === "high_risk") {
                records = records.filter(r => (r.score || 0) >= 40);
              }
              res.end(JSON.stringify({ records: records.slice(0, limit), total: records.length }));
            } catch (err) {
              logger.warn?.("[shadow-auditor] Events route failed:", err);
              res.statusCode = 500;
              res.setHeader("content-type", "application/json; charset=utf-8");
              res.end(JSON.stringify({ error: "Internal server error" }));
            }
          },
        }),
      "shadow-auditor: events route"
    );

    ctx.effect(
      () =>
        ctx.webServer.register({
          kind: "exact",
          path: "/dsh-shadow-auditor/export",
          handler: async (req, res) => {
            if (req.method !== "GET" && req.method !== "HEAD") {
              res.writeHead(405, {
                allow: "GET, HEAD",
                "content-type": "application/json; charset=utf-8",
              });
              res.end(JSON.stringify({ error: "Method Not Allowed" }));
              return;
            }
            const srvToken =
              ctx?.webServer?.token || process.env.DSH_AUTH_TOKEN || process.env.DSH_TOKEN;
            if (!isTrustedRequest(req, { expectedToken: srvToken })) {
              res.writeHead(403, { "content-type": "application/json; charset=utf-8" });
              res.end(JSON.stringify({ error: "Access denied: untrusted caller" }));
              return;
            }
            try {
              const url = new URL(req.url || "", "http://localhost");
              const format = url.searchParams.get("format") || "markdown";
              const sid = url.searchParams.get("sessionId");
              const rawLimit = parseInt(url.searchParams.get("limit") || "1000", 10);
              const limit = Math.min(Math.max(1, Number.isFinite(rawLimit) ? rawLimit : 1000), 5000);

              let records = recorder?.readAll
                ? await recorder.readAll({ limit, sessionId: sid, maxRecords: limit })
                : [];
              if (sid) {
                records = records.filter(r => r.sessionId === sid);
              }
              if (format === "json") {
                res.setHeader("content-type", "application/json; charset=utf-8");
                res.setHeader(
                  "content-disposition",
                  'attachment; filename=""'
                );
                res.end(JSON.stringify(records, null, 2));
              } else {
                const bills = buildSessionBills(records);
                const md = billsToMarkdown(bills);
                res.setHeader("content-type", "text/markdown; charset=utf-8");
                res.setHeader(
                  "content-disposition",
                  'attachment; filename=""'
                );
                res.end(md);
              }
            } catch (err) {
              logger.warn?.("[shadow-auditor] Export generation failed:", err);
              res.statusCode = 500;
              res.setHeader("content-type", "application/json; charset=utf-8");
              res.end(JSON.stringify({ error: "Failed to generate audit export" }));
            }
          },
        }),
      "shadow-auditor: export route"
    );
  } catch (err) {
    logger.warn?.("[shadow-auditor] Failed to register web endpoints:", err);
  }
}
