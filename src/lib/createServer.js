import getHandler from "./getHandler.js";
import httpProxy from "http-proxy";
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path, { join } from "node:path";
import os from "node:os";
import { fileURLToPath } from "url";

// Helper for file paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Server Stats State
const serverStats = {
  totalRequests: 0,
  startTime: Date.now(),
};

function getUptime() {
  const diff = Math.floor((Date.now() - serverStats.startTime) / 1000);
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function createServer(options) {
  options = options || {};

  const httpProxyOptions = {
    xfwd: true,
    secure: process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0",
  };

  if (options.httpProxyOptions) {
    Object.keys(options.httpProxyOptions).forEach(function (option) {
      httpProxyOptions[option] = options.httpProxyOptions[option];
    });
  }

  const proxyServer = httpProxy.createProxyServer(httpProxyOptions);
  const requestHandler = getHandler(options, proxyServer);
  let server;

  // CORS Helper
  const handleCors = (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization"
    );
    res.setHeader("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return true;
    }
    return false;
  };

  // Security Check Helper
  const isOriginAllowed = (origin, options) => {
    if (options.originWhitelist.includes("*")) return true;
    if (
      options.originWhitelist.length &&
      !options.originWhitelist.includes(origin)
    )
      return false;
    if (
      options.originBlacklist.length &&
      options.originBlacklist.includes(origin)
    )
      return false;
    return true;
  };

  // --- MAIN REQUEST LISTENER ---
  const mainListener = (req, res) => {
    const origin = req.headers.origin || "";

    // 1. PUBLIC ROUTES (Bypass Origin Check)
    // --------------------------------------

    // Route: /proxy (The Dashboard)
    if (req.url === "/proxy" || req.url === "/proxy/") {
      try {
        res.writeHead(200, { "Content-Type": "text/html" });
        return res.end(
          fs.readFileSync(join(__dirname, "../proxy.html"))
        );
      } catch (err) {
        res.writeHead(500);
        res.end("Dashboard file missing.");
        return;
      }
    }

    // Route: /api/stats (For the Dashboard Terminal)
    if (req.url === "/api/stats") {
      const stats = {
        requests: serverStats.totalRequests,
        uptime: getUptime(),
        memory:
          Math.round(process.memoryUsage().rss / 1024 / 1024) + " MB",
        host: os.hostname(),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(stats));
      return;
    }

    // 2. SECURITY & PROXY LOGIC
    // --------------------------------------

    // If not a public page, enforce Origin Security
    if (!isOriginAllowed(origin, options)) {
      res.writeHead(403, "Forbidden");
      res.end(
        `The origin "${origin}" was blacklisted by the operator of this proxy.`
      );
      return;
    }

    // Handle CORS preflight
    if (handleCors(req, res)) return;

    // Track Request for Dashboard
    serverStats.totalRequests++;

    // Forward to actual Proxy Handler
    requestHandler(req, res);
  };

  // Server Creation
  if (options.httpsOptions) {
    server = https.createServer(options.httpsOptions, mainListener);
  } else {
    server = http.createServer(mainListener);
  }

  // Error Handling
  proxyServer.on("error", function (err, req, res) {
    console.error("Proxy error:", err);
    if (res.headersSent) {
      if (!res.writableEnded) {
        res.end();
      }
      return;
    }

    const headerNames = res.getHeaderNames
      ? res.getHeaderNames()
      : Object.keys(res._headers || {});
    headerNames.forEach(function (name) {
      res.removeHeader(name);
    });

    res.writeHead(404, { "Access-Control-Allow-Origin": "*" });
    res.end("Not found because of proxy error: " + err);
  });

  return server;
}