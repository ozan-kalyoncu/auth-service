import type { Express } from 'express';

/**
 * Lists every route the app actually serves, as "METHOD /path" strings with
 * Express-style params (":id") rewritten to OpenAPI-style ("{id}").
 *
 * Express 4 keeps no list of full paths: each router holds a stack of layers,
 * and a mounted sub-router only remembers its prefix as a compiled regexp. So
 * this walks the stack recursively and recovers each prefix from that regexp.
 * It reaches into Express internals, which is acceptable in a test helper (a
 * framework upgrade breaks a test, loudly) but would not be in app code.
 */
export function listRoutes(app: Express): string[] {
  // `_router` is created lazily by Express on the first app.use / app.get.
  const root = (app as unknown as { _router: { stack: Layer[] } })._router;
  return walk(root.stack, '').sort();
}

interface Layer {
  route?: { path: string; methods: Record<string, boolean> };
  regexp: RegExp & { fast_slash?: boolean };
  handle: { stack?: Layer[] };
}

function walk(stack: Layer[], prefix: string): string[] {
  return stack.flatMap((layer) => {
    if (layer.route) {
      const path = (prefix + (layer.route.path === '/' ? '' : layer.route.path)) || '/';
      return Object.keys(layer.route.methods)
        .filter((method) => method !== '_all')
        .map((method) => `${method.toUpperCase()} ${path.replace(/:(\w+)/g, '{$1}')}`);
    }
    // Only sub-routers have a stack; plain middleware (helmet, static files) is skipped.
    if (layer.handle.stack) return walk(layer.handle.stack, prefix + mountPath(layer));
    return [];
  });
}

/** Recovers "/health" from the regexp Express 4 compiles for `router.use('/health', ...)`. */
function mountPath(layer: Layer): string {
  if (layer.regexp.fast_slash) return '';
  const match = layer.regexp.source.match(/^\^(.*?)\\\/\?\(\?=\\\/\|\$\)$/);
  if (!match) throw new Error(`Cannot recover a mount path from ${layer.regexp}`);
  return match[1].replace(/\\\//g, '/');
}
