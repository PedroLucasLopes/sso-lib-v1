import type { Request } from 'express';

export function isPageNavigation(req: Request): boolean {
  const destination = req.headers['sec-fetch-dest'];

  if (typeof destination === 'string') return destination === 'document';

  return (req.headers.accept ?? '').includes('text/html');
}
