import type { RedirectHop, ScanOptions } from './types.js';

export interface FetchResult {
  finalUrl: string;
  statusCode: number;
  headers: Record<string, string>;
  redirectChain: RedirectHop[];
}

const DEFAULT_UA = 'HeaderVet/1.0 (Security Header Scanner)';

export async function fetchHeaders(url: string, opts: ScanOptions = {}): Promise<FetchResult> {
  const timeout = opts.timeout ?? 10000;
  const ua = opts.userAgent ?? DEFAULT_UA;
  const followRedirects = opts.followRedirects ?? true;
  const redirectChain: RedirectHop[] = [];

  let currentUrl = url;
  const maxRedirects = 10;

  for (let i = 0; i < maxRedirects; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const reqHeaders: Record<string, string> = { 'User-Agent': ua };
      if (opts.cookie) {
        reqHeaders['Cookie'] = opts.cookie;
      }
      if (opts.customHeaders) {
        Object.assign(reqHeaders, opts.customHeaders);
      }

      const res = await fetch(currentUrl, {
        method: 'GET',
        headers: reqHeaders,
        redirect: 'manual',
        signal: controller.signal,
      });

      const hdrs = headersToRecord(res.headers);

      if (followRedirects && res.status >= 300 && res.status < 400 && hdrs['location']) {
        redirectChain.push({ url: currentUrl, statusCode: res.status, headers: hdrs });
        const loc = hdrs['location'];
        currentUrl = loc.startsWith('http') ? loc : new URL(loc, currentUrl).href;
        continue;
      }

      return { finalUrl: currentUrl, statusCode: res.status, headers: hdrs, redirectChain };
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error(`Too many redirects (>${maxRedirects}) for ${url}`);
}

function headersToRecord(h: Headers): Record<string, string> {
  const rec: Record<string, string> = {};
  h.forEach((v, k) => { rec[k.toLowerCase()] = v; });
  return rec;
}
