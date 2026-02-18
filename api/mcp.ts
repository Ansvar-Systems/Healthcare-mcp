import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { VercelRequest, VercelResponse } from '@vercel/node';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { computeAboutContext, openDatabase } from '../src/db.js';
import { registerTools } from '../src/tools/registry.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_PATH = join(__dirname, '..', 'package.json');
const pkg = JSON.parse(readFileSync(PKG_PATH, 'utf-8')) as { version: string };

const db = openDatabase(true);
const aboutContext = computeAboutContext(pkg.version);
const sessions = new Map<string, StreamableHTTPServerTransport>();

function setCors(res: VercelResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, mcp-session-id');
}

function createMCPServer(): Server {
  const server = new Server(
    {
      name: 'healthcare-mcp',
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

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  setCors(res);

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  const sessionIdHeader = req.headers['mcp-session-id'];
  const sessionId = Array.isArray(sessionIdHeader) ? sessionIdHeader[0] : sessionIdHeader;

  try {
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

      if (transport.sessionId) {
        sessions.set(transport.sessionId, transport);
      }

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

    res.status(404).json({ error: 'Session not found or unsupported method' });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to handle MCP request',
      details: error instanceof Error ? error.message : String(error),
    });
  }
}
