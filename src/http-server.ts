#!/usr/bin/env node

import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { openDatabase, DB_PATH } from './db.js';
import { getHealthPayload } from './health.js';
import { registerTools } from './tools/registry.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const sourcePkgPath = join(__dirname, '..', 'package.json');
const distPkgPath = join(__dirname, '..', '..', 'package.json');
const PKG_PATH = existsSync(sourcePkgPath) ? sourcePkgPath : distPkgPath;
const pkg = JSON.parse(readFileSync(PKG_PATH, 'utf-8')) as { version: string };

const PORT = Number(process.env.PORT || '3000');
const SERVER_NAME = 'healthcare-mcp';

const db = openDatabase(true);

function computeAboutContext() {
  let fingerprint = 'unknown';
  let dbBuilt = new Date().toISOString();

  try {
    const bytes = readFileSync(DB_PATH);
    fingerprint = createHash('sha256').update(bytes).digest('hex').slice(0, 12);
    dbBuilt = statSync(DB_PATH).mtime.toISOString();
  } catch {
    // Non-fatal
  }

  return {
    version: pkg.version,
    fingerprint,
    dbBuilt,
  };
}

const aboutContext = computeAboutContext();
const sessions = new Map<string, StreamableHTTPServerTransport>();

function createMCPServer(): Server {
  const server = new Server(
    {
      name: SERVER_NAME,
      version: pkg.version,
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  registerTools(server, db, aboutContext);
  return server;
}

function setCors(res: ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, mcp-session-id');
}

function handleHealth(_req: IncomingMessage, res: ServerResponse): void {
  setCors(res);
  const staleThresholdDays = Number(process.env.HEALTHCARE_STALE_DAYS ?? '45');
  const payload = getHealthPayload(db, staleThresholdDays);
  const statusCode = payload.status === 'degraded' ? 503 : 200;

  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      status: payload.status,
      server: SERVER_NAME,
      version: pkg.version,
      database: payload.database,
      source_freshness_days: payload.source_freshness_days,
      build_age_days: payload.build_age_days,
      stale_threshold_days: payload.stale_threshold_days,
    }),
  );
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  setCors(res);

  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (req.method === 'POST') {
    if (sessionId && sessions.has(sessionId)) {
      await sessions.get(sessionId)!.handleRequest(req, res);
      return;
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });
    const server = createMCPServer();
    await server.connect(transport);

    transport.onclose = () => {
      if (transport.sessionId) {
        sessions.delete(transport.sessionId);
      }
    };

    await transport.handleRequest(req, res);

    if (transport.sessionId) {
      sessions.set(transport.sessionId, transport);
    }
    return;
  }

  if ((req.method === 'GET' || req.method === 'DELETE') && sessionId && sessions.has(sessionId)) {
    await sessions.get(sessionId)!.handleRequest(req, res);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Session not found or unsupported MCP method' }));
}

const httpServer = createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`);

  try {
    if (req.method === 'OPTIONS') {
      setCors(res);
      res.writeHead(204);
      res.end();
      return;
    }

    if (url.pathname === '/health' && req.method === 'GET') {
      handleHealth(req, res);
      return;
    }

    if (url.pathname === '/mcp') {
      await handleMcp(req, res);
      return;
    }

    setCors(res);
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  } catch (error) {
    setCors(res);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        error: 'Internal server error',
        details: error instanceof Error ? error.message : String(error),
      }),
    );
  }
});

httpServer.listen(PORT, () => {
  console.log(`Healthcare MCP HTTP server listening on port ${PORT}`);
});
