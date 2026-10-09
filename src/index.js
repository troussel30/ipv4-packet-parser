/**
 * @module ipv4-packet-parser
 *
 * Public entry point for the IPv4 Packet Parser library.
 *
 * Design decision: every public symbol is re-exported here so that
 * downstream callers import from a single module path
 * ("ipv4-packet-parser"). Internal modules (like core.js) are intentionally
 * not exposed at the top level; only the re-exports below are the public API.
 */

export {
  parseIpv4,
  PROTOCOL_NUMBERS,
  getProtocolName,
  INVALID_PARSE,
  isInvalidParse,
} from "./core.js";
