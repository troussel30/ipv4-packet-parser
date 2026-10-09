/**
 * @module core
 *
 * Core IPv4 datagram decoder.
 *
 * Choice: this parser is intentionally strict about buffers shorter than 20
 * bytes (the minimum IHL), and treats any buffer that cannot hold its own
 * declared header length as garbage. We DO NOT validate checksums here — the
 * brief lists the fields we report, and adding checksum verification would
 * surface in the returned shape, which is a public API change we have not
 * agreed to. Callers who need integrity checks can do their own computation.
 */

/**
 * Read-only map of common IPv4 protocol numbers to human-readable names.
 *
 * Kept small on purpose. Covering every assignment IANA publishes would
 * require a lookup table approaching a thousand entries; this covers the
 * protocols that appear in essentially every textbook example and the ones a
 * network operator will encounter on a typical inspection task. Unknown
 * numbers fall back to "unknown" rather than being invented.
 */
export const PROTOCOL_NUMBERS = Object.freeze({
  1: "icmp",
  2: "igmp",
  6: "tcp",
  17: "udp",
  41: "ipv6",
  47: "gre",
  50: "esp",
  51: "ah",
  58: "ipv6-icmp",
  89: "ospf",
  132: "sctp",
});

/**
 * @param {number} proto - IPv4 protocol number from the header byte.
 * @returns {string} canonical lowercase name, or "unknown" if unmapped.
 */
export function getProtocolName(proto) {
  if (Number.isInteger(proto) && proto >= 0 && proto <= 255) {
    return PROTOCOL_NUMBERS[proto] ?? "unknown";
  }
  return "unknown";
}

/**
 * Sentinel returned by {@link parseIpv4} when the buffer is not a
 * decodable IPv4 datagram.
 *
 * Frozen so identity comparison (=== INVALID_PARSE) is safe and accidental
 * mutation is blocked. Exported because downstream code needs to distinguish
 * "this is the parse-failed marker" from "this is a real result with empty
 * options", which is a legitimate parse outcome for a minimal 20-byte header.
 */
export const INVALID_PARSE = Object.freeze({
  invalid: true,
  reason: "invalid",
});

/**
 * @param {*} value - anything returned by parseIpv4.
 * @returns {boolean} true if value is the INVALID_PARSE sentinel.
 */
export function isInvalidParse(value) {
  return value === INVALID_PARSE;
}

/**
 * Convert a 4-byte sequence to dotted-decimal notation.
 *
 * @param {Uint8Array} buf - source buffer.
 * @param {number} off - byte offset of the first octet.
 * @returns {string} dotted-decimal string like "10.0.0.1".
 */
function dotted(buf, off) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

/**
 * Decode the IP options region (zero or more bytes between the 20-byte fixed
 * header and the IHL-gated end of the header) into 32-bit words.
 *
 * IPv4 options are always a whole number of 32-bit words, so we emit them as
 * a list of unsigned 32-bit integers. The brief calls for "options" in the
 * result; representing them as raw 32-bit words is the smallest faithful
 * interpretation that requires no additional protocol parsing. We deliberately
 * do NOT walk the option type/length/value structure, because decoding each
 * option type is a separate library's worth of work and the caller did not ask
 * for that.
 *
 * @param {Uint8Array} buf - packet buffer.
 * @param {number} start - first byte after the fixed header (20).
 * @param {number} end - last byte of the header (ihl * 4).
 * @returns {number[]} big-endian 32-bit words.
 */
function decodeOptions(buf, start, end) {
  if (end <= start) return [];
  const opts = [];
  for (let i = start; i + 4 <= end; i += 4) {
    opts.push(
      (buf[i] * 0x1000000) +
        (buf[i + 1] * 0x10000) +
        (buf[i + 2] * 0x100) +
        buf[i + 3],
    );
  }
  return opts;
}

/**
 * Decode an IPv4 datagram from a raw byte buffer.
 *
 * @param {Uint8Array|Buffer} input - raw IP datagram starting with the
 *   version/IHL byte. Buffer-like: a typed array with numeric indices and a
 *   .length property. We use .length and integer indexing, so Uint8Array,
 *   Buffer, and Uint8Array views on a shared ArrayBuffer all work.
 * @returns {object} either {@link INVALID_PARSE} (if the buffer is malformed)
 *   or a parsed datagram object with the following fields:
 *   - version {number}   always 4 on a successful parse
 *   - ihl {number}       header length in 32-bit words (integer 5-15)
 *   - headerLength {number}  ihl * 4, the header size in bytes
 *   - tos {number}       full DSCP/ECN byte as a raw 0-255 integer
 *   - totalLength {number}  value of the Total Length field from the header
 *   - identification {number}  16-bit identification field
 *   - flags {number}     3 flag bits as an integer 0-7
 *   - fragmentOffset {number}  13-bit fragment offset, in 8-byte units
 *   - ttl {number}       8-bit TTL
 *   - protocol {number}  raw protocol number (0-255)
 *   - protocolName {string}  canonical lowercase name or "unknown"
 *   - sourceAddress {string}  dotted-decimal source IP
 *   - destinationAddress {string}  dotted-decimal destination IP
 *   - options {number[]}  header options as 32-bit big-endian words
 *   - payloadOffset {number}  byte offset of the payload (= headerLength)
 *
 * We do not return the raw payload bytes; we return the offset, which lets the
 * caller decide how to slice or view the buffer without forcing a copy.
 */
export function parseIpv4(input) {
  if (!input || typeof input.length !== "number" || input.length < 20) {
    return INVALID_PARSE;
  }

  const buf = input;

  const v0 = buf[0] >>> 4;
  const ihl = buf[0] & 0x0f;

  // The version byte must say IPv4. If it doesn't, this isn't an IPv4
  // datagram and reporting fields would mislead the caller.
  if (v0 !== 4) return INVALID_PARSE;

  // IHL is in 32-bit words; minimum legal value is 5 (20 bytes). We reject
  // any IHL below 5 because the fixed IPv4 header is 20 bytes and the parser
  // cannot trust a header that claims to be shorter than its own fixed part.
  if (ihl < 5 || ihl > 15) return INVALID_PARSE;

  const headerLength = ihl * 4;

  // If the buffer cannot even hold the declared header, the packet is
  // truncated beyond what we can trust.
  if (buf.length < headerLength) return INVALID_PARSE;

  const tos = buf[1];
  const totalLength = (buf[2] << 8) | buf[3];
  const identification = (buf[4] << 8) | buf[5];
  const flagsFrag = (buf[6] << 8) | buf[7];
  const flags = (flagsFrag >>> 13) & 0x07;
  const fragmentOffset = flagsFrag & 0x1fff;
  const ttl = buf[8];
  const protocol = buf[9];
  const sourceAddress = dotted(buf, 12);
  const destinationAddress = dotted(buf, 16);
  const options = decodeOptions(buf, 20, headerLength);

  return {
    version: 4,
    ihl,
    headerLength,
    tos,
    totalLength,
    identification,
    flags,
    fragmentOffset,
    ttl,
    protocol,
    protocolName: getProtocolName(protocol),
    sourceAddress,
    destinationAddress,
    options,
    payloadOffset: headerLength,
  };
}
