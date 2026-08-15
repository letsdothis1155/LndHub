/**
 * Node file-system sources.
 *
 * Kept out of `src/index.ts` on purpose: importing the library in a browser
 * must never pull `node:fs`. Reach these through the `./node` subpath.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import type { ApkSource } from '../batch.js';

const APK_EXTENSIONS = ['.apk', '.apks', '.apkm', '.jar', '.aab'];

function looksLikePackage(name: string): boolean {
  const lower = name.toLowerCase();
  return APK_EXTENSIONS.some((extension) => lower.endsWith(extension));
}

/** A source that reads one file lazily, so bytes are loaded only when scanned. */
export function fromPath(path: string, id?: string): ApkSource {
  return {
    id: id ?? path,
    load: async () => new Uint8Array(await readFile(path)),
  };
}

export interface FromDirectoryOptions {
  recursive?: boolean;
  /** Accept any file, not just APK-like extensions. */
  includeAll?: boolean;
}

/** Collects package files from a directory, sorted by path for stable output. */
export async function fromDirectory(
  directory: string,
  options: FromDirectoryOptions = {},
): Promise<ApkSource[]> {
  const { recursive = true, includeAll = false } = options;
  const root = resolve(directory);
  const found: string[] = [];

  const walk = async (current: string): Promise<void> => {
    const dirEntries = await readdir(current, { withFileTypes: true });
    for (const dirEntry of dirEntries.sort((a, b) => a.name.localeCompare(b.name))) {
      const full = join(current, dirEntry.name);
      if (dirEntry.isDirectory()) {
        if (recursive) await walk(full);
      } else if (dirEntry.isFile() && (includeAll || looksLikePackage(dirEntry.name))) {
        found.push(full);
      }
    }
  };

  await walk(root);
  // Relative ids keep reports portable across machines.
  return found.map((path) => fromPath(path, relative(root, path) || path));
}

/**
 * Expands CLI arguments — each may be a file or a directory — into sources.
 */
export async function fromPaths(
  paths: string[],
  options: FromDirectoryOptions = {},
): Promise<ApkSource[]> {
  const sources: ApkSource[] = [];
  for (const path of paths) {
    const info = await stat(path);
    if (info.isDirectory()) sources.push(...(await fromDirectory(path, options)));
    else sources.push(fromPath(path));
  }
  return sources;
}
