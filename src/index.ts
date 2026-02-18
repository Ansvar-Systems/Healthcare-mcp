#!/usr/bin/env node

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { computeAboutContext, openDatabase } from './db.js';
import { registerTools } from './tools/registry.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const sourcePkgPath = join(__dirname, '..', 'package.json');
const distPkgPath = join(__dirname, '..', '..', 'package.json');
const PKG_PATH = existsSync(sourcePkgPath) ? sourcePkgPath : distPkgPath;
const pkg = JSON.parse(readFileSync(PKG_PATH, 'utf-8')) as { version: string };

async function main(): Promise<void> {
  const db = openDatabase(true);
  const context = computeAboutContext(pkg.version);

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

  registerTools(server, db, context);

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('Healthcare MCP server started');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
