// ------------------------------------------------------------------------------
// urlValidator.js
// Validates user-supplied URLs before they are fetched server-side, and provides
// SSRF-guarded HTTP/HTTPS agents. Rejects non-http(s) schemes, IP literals in
// private/loopback/link-local ranges (including decimal/hex/octal encodings), and
// hostnames that are obviously not on the public internet.
//
// The string-level validation (validatePublicImageUrl) is a fast first gate, but
// it cannot defend against DNS rebinding or HTTP redirects to private hosts. The
// guarded agents (getGuardedAgents) close that gap: they re-resolve and re-check
// the destination IP at *connect* time, so every redirect hop and every DNS
// answer is validated, not just the original hostname string.
// ------------------------------------------------------------------------------

const net = require('net');
const dns = require('dns');
const http = require('http');
const https = require('https');

function isPrivateIPv4(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return false;
    if (parts[0] === 10) return true;                                       // 10.0.0.0/8
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;  // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true;                  // 192.168.0.0/16
    if (parts[0] === 127) return true;                                      // loopback
    if (parts[0] === 169 && parts[1] === 254) return true;                  // link-local (incl. 169.254.169.254)
    if (parts[0] === 0) return true;                                        // 0.0.0.0/8
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true; // CGNAT
    return false;
}

function isPrivateIPv6(ip) {
    const lower = ip.toLowerCase().replace(/^\[|\]$/g, '');
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;      // unique local
    if (lower.startsWith('fe80')) return true;                              // link-local
    // IPv4-mapped IPv6 in dotted form (::ffff:127.0.0.1)
    const mappedDotted = lower.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (mappedDotted && isPrivateIPv4(mappedDotted[1])) return true;
    // IPv4-mapped IPv6 in hex form (::ffff:7f00:1) — node's URL normalizes to this
    const mappedHex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedHex) {
        const high = parseInt(mappedHex[1], 16);
        const low = parseInt(mappedHex[2], 16);
        const dotted = `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
        if (isPrivateIPv4(dotted)) return true;
    }
    return false;
}

// Returns true if a resolved IP string (v4 or v6) is in a private/reserved range.
function isBlockedIp(ip) {
    const clean = ip.replace(/^\[|\]$/g, '');
    if (net.isIPv4(clean)) return isPrivateIPv4(clean);
    if (net.isIPv6(clean)) return isPrivateIPv6(clean);
    return false;
}

// Parse a single host component as an integer, honoring decimal, hex (0x...) and
// octal (leading-zero) notations the same way the platform resolver does.
// Returns NaN for anything that isn't a pure numeric token.
function parseHostInt(token) {
    if (/^0x[0-9a-f]+$/i.test(token)) return parseInt(token, 16);
    if (/^0[0-7]+$/.test(token)) return parseInt(token, 8);
    if (/^[0-9]+$/.test(token)) return parseInt(token, 10);
    return NaN;
}

// Normalize numeric/encoded IPv4 hostnames (e.g. "2130706433", "0x7f000001",
// "0177.0.0.1") to canonical dotted-decimal so the private-range check can see
// them. Real DNS hostnames never consist solely of numeric tokens, so this only
// matches things that are genuinely IPv4 literals in disguise. Returns null when
// the host is not a numeric IPv4 form.
function normalizeNumericIPv4(host) {
    const parts = host.split('.');
    if (parts.length === 1) {
        const n = parseHostInt(parts[0]);
        if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) return null;
        return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
    }
    if (parts.length === 4) {
        const nums = parts.map(parseHostInt);
        if (nums.some(n => !Number.isInteger(n) || n < 0 || n > 0xff)) return null;
        return nums.join('.');
    }
    return null;
}

// Validates that a URL is safe to fetch from a public-facing server.
// Options:
//   allowedHosts: string[] of hostnames that may bypass the private-IP check.
//   allowPrivate: when true, skip the private/reserved checks entirely but STILL
//                 enforce a valid http(s) absolute URL. Used for the opt-in
//                 ALLOW_INSECURE_OVERLAY_URLS=true mode so that local file paths,
//                 file:// and data: inputs are still rejected.
// Returns the normalized URL string on success, throws on failure.
function validatePublicImageUrl(input, { allowedHosts = [], allowPrivate = false } = {}) {
    if (!input || typeof input !== 'string') {
        throw new Error('URL must be a non-empty string');
    }

    let parsed;
    try {
        parsed = new URL(input);
    } catch {
        throw new Error('URL is not a valid absolute URL');
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`URL protocol '${parsed.protocol}' is not allowed (use http or https)`);
    }

    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    if (!hostname) {
        throw new Error('URL is missing a hostname');
    }

    if (allowedHosts.includes(hostname.toLowerCase())) {
        return parsed.toString();
    }

    if (allowPrivate) {
        return parsed.toString();
    }

    // Resolve the hostname to an IP literal when it is one (directly or via a
    // numeric/hex/octal encoding) and block private/reserved ranges.
    let ipLiteral = null;
    if (net.isIP(hostname)) {
        ipLiteral = hostname;
    } else {
        const normalized = normalizeNumericIPv4(hostname);
        if (normalized && net.isIP(normalized)) {
            ipLiteral = normalized;
        }
    }

    if (ipLiteral) {
        if (isBlockedIp(ipLiteral)) {
            throw new Error('URL points to a private or reserved address');
        }
    } else {
        const lower = hostname.toLowerCase();
        if (lower === 'localhost' ||
            lower.endsWith('.localhost') ||
            lower.endsWith('.local') ||
            lower.endsWith('.internal')) {
            throw new Error('URL points to a private or reserved hostname');
        }
    }

    return parsed.toString();
}

// ------------------------------------------------------------------------------
// SSRF-guarded agents
// ------------------------------------------------------------------------------

// A drop-in dns.lookup replacement that rejects any answer pointing at a private
// or reserved address. Injected into the socket connection so it runs for the
// initial request AND every redirect hop, defeating DNS-rebinding and
// redirect-to-internal SSRF that string validation alone cannot catch.
function guardedLookup(hostname, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }
    dns.lookup(hostname, options, (err, address, family) => {
        if (err) return callback(err, address, family);
        const answers = Array.isArray(address) ? address : [{ address, family }];
        for (const entry of answers) {
            if (isBlockedIp(entry.address)) {
                return callback(new Error(
                    `Blocked request to private/reserved address ${entry.address} (host: ${hostname})`
                ));
            }
        }
        callback(null, address, family);
    });
}

// Node only invokes `lookup` for hostnames that require DNS resolution; literal
// IP destinations (including redirect targets like http://127.0.0.1/) connect
// directly and would otherwise bypass guardedLookup. So we also reject blocked IP
// literals here, before the socket connects.
function rejectIfBlockedLiteral(options, callback) {
    const host = options.host || options.hostname;
    if (host && net.isIP(host.replace(/^\[|\]$/g, '')) && isBlockedIp(host)) {
        const err = new Error(`Blocked request to private/reserved address ${host}`);
        const socket = new net.Socket();
        process.nextTick(() => {
            if (typeof callback === 'function') callback(err);
            socket.destroy(err);
        });
        return socket;
    }
    return null;
}

class GuardedHttpAgent extends http.Agent {
    createConnection(options, callback) {
        return rejectIfBlockedLiteral(options, callback)
            || super.createConnection({ ...options, lookup: guardedLookup }, callback);
    }
}

class GuardedHttpsAgent extends https.Agent {
    createConnection(options, callback) {
        return rejectIfBlockedLiteral(options, callback)
            || super.createConnection({ ...options, lookup: guardedLookup }, callback);
    }
}

const guardedHttpAgent = new GuardedHttpAgent();
const guardedHttpsAgent = new GuardedHttpsAgent();

// Returns axios-compatible agent options that validate the destination IP at
// connect time. Pass allowPrivate: true to opt out (used only when the operator
// has explicitly allow-listed a private host via ALLOW_INSECURE_OVERLAY_URLS).
function getGuardedAgents(allowPrivate = false) {
    if (allowPrivate) return {};
    return { httpAgent: guardedHttpAgent, httpsAgent: guardedHttpsAgent };
}

module.exports = {
    validatePublicImageUrl,
    getGuardedAgents,
    isBlockedIp
};
