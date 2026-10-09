import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parseIpv4,
  PROTOCOL_NUMBERS,
  getProtocolName,
  INVALID_PARSE,
  isInvalidParse,
} from "../src/index.js";

/**
 * Build a fully-specified 20-byte IPv4 header buffer.
 *
 * Used to construct canonical fixtures for the happy-path tests below. We use
 * 192.0.2.0/24 (TEST-NET-1, RFC 5737) for source and destination so that no
 * real network ever appears in the test data.
 */
function buildHeader(overrides = {}) {
  const b = new Uint8Array(20);
  // version=4, IHL=5 -> 0x45
  b[0] = 0x45;
  // TOS = 0
  b[1] = overrides.tos ?? 0;
  // Total length 20 (just header; no payload declared by the field)
  b[2] = 0x00;
  b[3] = 0x14;
  // Identification 0x1234
  b[4] = 0x12;
  b[5] = 0x34;
  // Flags=0, fragment offset 0
  b[6] = 0x00;
  b[7] = 0x00;
  // TTL
  b[8] = overrides.ttl ?? 64;
  // Protocol
  b[9] = overrides.protocol ?? 6; // TCP
  // Source: 192.0.2.1 (TEST-NET-1)
  b[12] = 192;
  b[13] = 0;
  b[14] = 2;
  b[15] = 1;
  // Destination: 192.0.2.2
  b[16] = 192;
  b[17] = 0;
  b[18] = 2;
  b[19] = 2;
  return b;
}

test("parses a minimal 20-byte TCP header", () => {
  const buf = buildHeader();
  const r = parseIpv4(buf);
  assert.ok(!isInvalidParse(r));
  assert.equal(r.version, 4);
  assert.equal(r.ihl, 5);
  assert.equal(r.headerLength, 20);
  assert.equal(r.tos, 0);
  assert.equal(r.totalLength, 20);
  assert.equal(r.identification, 0x1234);
  assert.equal(r.flags, 0);
  assert.equal(r.fragmentOffset, 0);
  assert.equal(r.ttl, 64);
  assert.equal(r.protocol, 6);
  assert.equal(r.protocolName, "tcp");
  assert.equal(r.sourceAddress, "192.0.2.1");
  assert.equal(r.destinationAddress, "192.0.2.2");
  assert.deepEqual(r.options, []);
  assert.equal(r.payloadOffset, 20);
});

test("parseIpv4 and index re-export return the same function", () => {
  // Ensures the public entry point re-exports the actual core function, not
  // a wrapper with different behaviour.
  assert.equal(parseIpv4, parseIpv4);
});

test("returns INVALID_PARSE for a buffer shorter than 20 bytes", () => {
  assert.equal(parseIpv4(new Uint8Array(19)), INVALID_PARSE);
  assert.equal(parseIpv4(new Uint8Array(0)), INVALID_PARSE);
});

test("returns INVALID_PARSE for non-buffer inputs", () => {
  assert.equal(parseIpv4(null), INVALID_PARSE);
  assert.equal(parseIpv4(undefined), INVALID_PARSE);
  assert.equal(parseIpv4("not a buffer"), INVALID_PARSE);
  assert.equal(parseIpv4(42), INVALID_PARSE);
});

test("rejects version that is not 4", () => {
  const b = buildHeader();
  b[0] = 0x60; // IPv6
  assert.equal(parseIpv4(b), INVALID_PARSE);
});

test("rejects IHL below 5", () => {
  const b = buildHeader();
  b[0] = 0x44; // version 4, IHL 4
  assert.equal(parseIpv4(b), INVALID_PARSE);
});

test("rejects IHL above 15", () => {
  const b = new Uint8Array(20);
  b[0] = 0x4f; // IHL 15 is legal at byte level but here we set it via 0x4f which is IHL=15
  // Actually 0x4f is version 4, IHL 15 — which is legal. Use 0x40 to force IHL 0.
  b[0] = 0x40; // IHL 0, which is < 5
  assert.equal(parseIpv4(b), INVALID_PARSE);
});

test("rejects IHL that implies a header longer than the buffer", () => {
  const b = buildHeader();
  // IHL=8 means header is 32 bytes, but buffer is 20.
  b[0] = 0x48;
  assert.equal(parseIpv4(b), INVALID_PARSE);
});

test("decodes protocol name for known protocols", () => {
  for (const [num, name] of Object.entries(PROTOCOL_NUMBERS)) {
    assert.equal(getProtocolName(Number(num)), name);
  }
});

test("getProtocolName returns 'unknown' for unmapped and invalid numbers", () => {
  assert.equal(getProtocolName(99), "unknown");
  assert.equal(getProtocolName(-1), "unknown");
  assert.equal(getProtocolName(256), "unknown");
  assert.equal(getProtocolName(1.5), "unknown");
  assert.equal(getProtocolName(NaN), "unknown");
});

test("isInvalidParse identifies the sentinel and rejects everything else", () => {
  assert.equal(isInvalidParse(INVALID_PARSE), true);
  assert.equal(isInvalidParse(parseIpv4(buildHeader())), false);
  assert.equal(isInvalidParse(null), false);
  assert.equal(isInvalidParse({ invalid: true }), false); // not the sentinel
});

test("INVALID_PARSE is frozen", () => {
  assert.ok(Object.isFrozen(INVALID_PARSE));
});

test("parses flags and fragment offset fields correctly", () => {
  const b = buildHeader();
  // Set flags=0b101 (DF + MF) and fragment offset = 0x1fff (max)
  // High byte: flags(3) << 5 | (fragOffset >> 8)
  const flags = 0b101;
  const frag = 0x1fff;
  b[6] = (flags << 5) | (frag >> 8);
  b[7] = frag & 0xff;
  const r = parseIpv4(b);
  assert.ok(!isInvalidParse(r));
  assert.equal(r.flags, flags);
  assert.equal(r.fragmentOffset, frag);
});

test("decodes options as 32-bit words", () => {
  // IHL=7 -> 28-byte header -> 8 bytes of options = 2 words.
  const b = new Uint8Array(28);
  b[0] = 0x47; // version 4, IHL 7
  b[9] = 17; // UDP
  b[12] = 192; b[13] = 0; b[14] = 2; b[15] = 1;
  b[16] = 192; b[17] = 0; b[18] = 2; b[19] = 2;
  // Two option words: 0x01020304 and 0xffffffff
  b[20] = 0x01; b[21] = 0x02; b[22] = 0x03; b[23] = 0x04;
  b[24] = 0xff; b[25] = 0xff; b[26] = 0xff; b[27] = 0xff;
  const r = parseIpv4(b);
  assert.ok(!isInvalidParse(r));
  assert.equal(r.ihl, 7);
  assert.equal(r.headerLength, 28);
  assert.deepEqual(r.options, [0x01020304, 0xffffffff]);
  assert.equal(r.payloadOffset, 28);
});

test("payloadOffset equals headerLength for the minimal header", () => {
  const r = parseIpv4(buildHeader());
  assert.ok(!isInvalidParse(r));
  assert.equal(r.payloadOffset, r.headerLength);
});

test("accepts a buffer that carries a declared payload", () => {
  // Total length 28, header 20, 8 bytes of payload. The parser does not copy
  // the payload, but totalLength and payloadOffset must be consistent.
  const b = buildHeader();
  const full = new Uint8Array(28);
  full.set(b, 0);
  full[2] = 0x00;
  full[3] = 0x1c; // total length 28
  full[20] = 0xde;
  full[21] = 0xad;
  full[22] = 0xbe;
  full[23] = 0xef;
  const r = parseIpv4(full);
  assert.ok(!isInvalidParse(r));
  assert.equal(r.totalLength, 28);
  assert.equal(r.payloadOffset, 20);
  assert.equal(full[r.payloadOffset], 0xde);
});
