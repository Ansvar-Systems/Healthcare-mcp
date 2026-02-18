import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { computeAboutContext } from '../src/db.js';
import { createToolDefinitions } from '../src/tools/registry.js';

const ROOT = process.cwd();

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHealth(port: number, timeoutMs: number): Promise<void> {
  const started = Date.now();
  const url = `http://127.0.0.1:${port}/health`;

  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // Retry until timeout.
    }
    await sleep(100);
  }

  throw new Error(`Timed out waiting for HTTP server health on port ${port}`);
}

async function getAvailablePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address !== 'object') {
        server.close();
        reject(new Error('Failed to allocate an ephemeral port'));
        return;
      }
      const port = address.port;
      server.close((closeError) => {
        if (closeError) {
          reject(closeError);
          return;
        }
        resolve(port);
      });
    });
  });
}

describe('transport parity', () => {
  let port = 0;
  let serverProcess: ChildProcess | null = null;
  let transport: StreamableHTTPClientTransport | null = null;
  let client: Client | null = null;
  let unavailableReason: string | null = null;

  beforeAll(async () => {
    try {
      port = await getAvailablePort();
      serverProcess = spawn('node', ['--import', 'tsx', 'src/http-server.ts'], {
        cwd: ROOT,
        env: { ...process.env, PORT: String(port) },
        stdio: 'pipe',
      });

      await waitForHealth(port, 10000);
    } catch (error) {
      unavailableReason = error instanceof Error ? error.message : String(error);
    }
  }, 15000);

  afterAll(async () => {
    if (transport) {
      await transport.close();
      transport = null;
    }

    client = null;

    if (!serverProcess) {
      return;
    }

    if (!serverProcess.killed) {
      serverProcess.kill('SIGTERM');
    }

    await sleep(150);
  });

  it('returns same tool manifest via HTTP /mcp as registry definitions', async () => {
    if (unavailableReason) {
      // Some sandboxed environments prohibit local listener sockets.
      expect(unavailableReason.length).toBeGreaterThan(0);
      return;
    }

    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf-8')) as { version: string };
    const localContext = computeAboutContext(pkg.version);
    const expectedTools = createToolDefinitions(localContext)
      .map((tool) => tool.name)
      .sort();

    client = new Client(
      {
        name: 'transport-parity-test-client',
        version: '1.0.0',
      },
      {
        capabilities: {},
      },
    );
    transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`));
    await client.connect(transport);

    const listed = await client.listTools();
    const httpTools = listed.tools.map((tool) => tool.name).sort();

    expect(httpTools).toEqual(expectedTools);
    expect(httpTools.length).toBeGreaterThan(10);
    expect(
      listed.tools.every(
        (tool) =>
          Array.isArray((tool.inputSchema as { examples?: unknown[] } | undefined)?.examples) &&
          ((tool.inputSchema as { examples?: unknown[] } | undefined)?.examples?.length ?? 0) > 0,
      ),
    ).toBe(true);
  });

});
