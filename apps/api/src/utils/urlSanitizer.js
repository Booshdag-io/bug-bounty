/**
 * Defensive URL sanitization and SSRF prevention utility.
 */

const DANGEROUS_PROTOCOLS = new Set([
  "javascript:",
  "vbscript:",
  "data:",
  "file:",
  "blob:",
  "about:"
]);

const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

/**
 * Checks whether an IP or hostname resolves to internal/private/loopback ranges.
 * @param {string} hostname
 * @returns {boolean}
 */
export function isPrivateHostname(hostname) {
  if (!hostname) return true;

  const lower = hostname.toLowerCase().trim();

  // Strip IPv6 brackets
  const cleanHost = lower.startsWith("[") && lower.endsWith("]")
    ? lower.slice(1, -1)
    : lower;

  if (
    cleanHost === "localhost" ||
    cleanHost.endsWith(".localhost") ||
    cleanHost.endsWith(".local") ||
    cleanHost.endsWith(".internal") ||
    cleanHost === "0.0.0.0" ||
    cleanHost === "::" ||
    cleanHost === "::1" ||
    cleanHost === "127.0.0.1"
  ) {
    return true;
  }

  // IPv4 range checks
  const ipv4Match = cleanHost.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [_, o1, o2, o3, o4] = ipv4Match.map(Number);
    if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) return true;

    // 127.0.0.0/8 (Loopback)
    if (o1 === 127) return true;

    // 10.0.0.0/8 (Private)
    if (o1 === 10) return true;

    // 172.16.0.0/12 (Private)
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;

    // 192.168.0.0/16 (Private)
    if (o1 === 192 && o2 === 168) return true;

    // 169.254.0.0/16 (Link-local & AWS / GCP metadata 169.254.169.254)
    if (o1 === 169 && o2 === 254) return true;

    // 0.0.0.0/8 (Current network)
    if (o1 === 0) return true;

    // 100.64.0.0/10 (Shared address space / CGNAT)
    if (o1 === 100 && o2 >= 64 && o2 <= 127) return true;
  }

  // IPv6 checks (fc00::/7 unique local, fe80::/10 link-local)
  if (cleanHost.startsWith("fc") || cleanHost.startsWith("fd") || cleanHost.startsWith("fe80")) {
    return true;
  }

  return false;
}

/**
 * Validates whether a given URL is safe for external display and outgoing requests.
 * @param {string} urlString
 * @param {Object} [options]
 * @param {boolean} [options.allowPrivate=false] - Whether to allow private hostnames
 * @param {Set<string>} [options.allowedProtocols] - Set of allowed protocols
 * @returns {boolean}
 */
export function isSafeUrl(urlString, options = {}) {
  if (typeof urlString !== "string" || !urlString.trim()) {
    return false;
  }

  const trimmed = urlString.trim();

  // Fast rejection of dangerous protocol prefixes
  const lowerTrimmed = trimmed.toLowerCase();
  for (const proto of DANGEROUS_PROTOCOLS) {
    if (lowerTrimmed.startsWith(proto)) {
      return false;
    }
  }

  // Reject CRLF characters (Header injection / response splitting)
  if (/[\r\n\0]/.test(trimmed)) {
    return false;
  }

  try {
    const parsed = new URL(trimmed);
    const protocols = options.allowedProtocols || ALLOWED_PROTOCOLS;

    if (!protocols.has(parsed.protocol)) {
      return false;
    }

    if (!options.allowPrivate && isPrivateHostname(parsed.hostname)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Sanitizes a URL, returning a safe normalized URL or a fallback.
 * @param {string} urlString
 * @param {string|null} [fallback=null]
 * @param {Object} [options]
 * @returns {string|null}
 */
export function sanitizeUrl(urlString, fallback = null, options = {}) {
  if (!isSafeUrl(urlString, options)) {
    return fallback;
  }
  try {
    const parsed = new URL(urlString.trim());
    return parsed.href;
  } catch {
    return fallback;
  }
}
