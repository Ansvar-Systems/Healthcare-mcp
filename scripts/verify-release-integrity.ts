#!/usr/bin/env tsx

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

type PackageManifest = {
  name: string;
  version: string;
  mcpName?: string;
};

type ServerManifest = {
  name: string;
  version: string;
  package?: string;
};

function parseSemver(version: string): [number, number, number] | null {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    return null;
  }
  return [Number.parseInt(match[1], 10), Number.parseInt(match[2], 10), Number.parseInt(match[3], 10)];
}

function compareSemver(a: string, b: string): number {
  const av = parseSemver(a);
  const bv = parseSemver(b);
  if (!av || !bv) {
    return 0;
  }
  for (let i = 0; i < 3; i += 1) {
    if (av[i] > bv[i]) {
      return 1;
    }
    if (av[i] < bv[i]) {
      return -1;
    }
  }
  return 0;
}

async function main(): Promise<void> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const root = join(__dirname, '..');

  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf-8')) as PackageManifest;
  const server = JSON.parse(readFileSync(join(root, 'server.json'), 'utf-8')) as ServerManifest;

  const failures: string[] = [];
  const warnings: string[] = [];

  if (pkg.mcpName !== server.name) {
    failures.push(`mcpName mismatch: package.json=${pkg.mcpName ?? '(missing)'} server.json=${server.name}`);
  }

  if (pkg.version !== server.version) {
    failures.push(`version mismatch: package.json=${pkg.version} server.json=${server.version}`);
  }

  if (server.package && server.package !== pkg.name) {
    failures.push(`package mismatch: server.json.package=${server.package} package.json.name=${pkg.name}`);
  }

  const refName = process.env.GITHUB_REF_NAME;
  if (refName && refName.startsWith('v')) {
    const tagVersion = refName.slice(1);
    if (tagVersion !== pkg.version) {
      failures.push(`tag/version mismatch: tag=${refName} package.json.version=${pkg.version}`);
    }
  }

  const checkNpm = process.env.RELEASE_CHECK_NPM === '1';
  const strictRemote = process.env.RELEASE_CHECK_STRICT === '1';
  if (checkNpm) {
    try {
      const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg.name)}`);
      if (!response.ok) {
        throw new Error(`npm registry HTTP ${response.status}`);
      }
      const payload = (await response.json()) as { 'dist-tags'?: { latest?: string } };
      const latest = payload['dist-tags']?.latest;
      if (latest) {
        const cmp = compareSemver(pkg.version, latest);
        if (cmp < 0) {
          failures.push(
            `package version is behind npm latest: package.json.version=${pkg.version} npm.latest=${latest}`,
          );
        }
      }
      console.log(`npm.latest: ${latest ?? 'unknown'}`);
    } catch (error) {
      const message = `Unable to query npm registry: ${error instanceof Error ? error.message : String(error)}`;
      if (strictRemote) {
        failures.push(message);
      } else {
        warnings.push(message);
      }
    }
  }

  for (const warning of warnings) {
    console.warn(`⚠️ ${warning}`);
  }

  if (failures.length > 0) {
    console.error('❌ Release integrity verification failed:');
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }

  console.log('✅ Release integrity verification passed.');
}

main().catch((error) => {
  console.error(`❌ Release integrity verification crashed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
