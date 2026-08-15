/**
 * Node-only entry point (`@smart-realty/apk-inspect/node`).
 *
 * Separate from the main entry so a browser bundle never pulls `node:fs`.
 */

export * from './sources.js';
