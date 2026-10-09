# IPv4 Packet Parser

A small, zero-dependency TypeScript-free ESM library that decodes an IPv4 datagram buffer into its header fields: version, IHL, total length, protocol, source and destination addresses, options, and payload offset.

```js
import { parseIpv4, isInvalidParse, getProtocolName } from "ipv4-packet-parser";

// Construct a minimal 20-byte IPv4 header as a Uint8Array.
const bytes = new Uint8Array(20);
bytes[0] = 0x45;          // version 4, IHL 5
bytes[9] = 6;            // protocol TCP
bytes[12] = 192;         // source address 192.0.2.1
bytes[13] = 0;
bytes[14] = 2;
bytes[15] = 1;
bytes[16] = 192;         // destination address 192.0.2.2
bytes[17] = 0;
bytes[18] = 2;
bytes[19] = 2;

const result = parseIpv4(bytes);

if (isInvalidParse(result)) {
  // result === INVALID_PARSE; the buffer was not a decodable IPv4 datagram.
} else {
  console.log(result.version);           // 4
  console.log(result.ihl);               // header length in 32-bit words
  console.log(result.headerLength);      // ihl * 4, in bytes
  console.log(result.totalLength);       // value of the Total Length field
  console.log(result.protocol);          // raw protocol number, 0-255
  console.log(result.protocolName);      // canonical lowercase name, e.g. "tcp"
  console.log(result.sourceAddress);     // dotted-decimal, e.g. "192.0.2.1"
  console.log(result.destinationAddress);
  console.log(result.options);           // header options as 32-bit big-endian words
  console.log(result.payloadOffset);     // byte offset of the payload
}
```

## Exports

- `parseIpv4(input)` — decode a `Uint8Array` / `Buffer` into a datagram object, or return `INVALID_PARSE`.
- `INVALID_PARSE` — frozen sentinel returned when the buffer is not a decodable IPv4 datagram.
- `isInvalidParse(value)` — `true` iff `value === INVALID_PARSE`.
- `getProtocolName(proto)` — canonical lowercase name for a protocol number; `"unknown"` for unmapped or invalid inputs.
- `PROTOCOL_NUMBERS` — frozen read-only map of the protocol numbers this library knows (icmp, igmp, tcp, udp, ipv6, gre, esp, ah, ipv6-icmp, ospf, sctp).

## Why this exists

The problem is narrow: you have a raw IPv4 datagram in a `Uint8Array` and you want the header fields out, without pulling in a full packet dissection library. This library does exactly that and nothing more. The trade-off is that it does not validate the header checksum, reassemble fragments, or decode the type-length-value structure of individual IP options — each of those is a separate concern and exposing them would widen the returned shape beyond what the caller asked for.

Options are returned as a list of 32-bit big-endian integers because IPv4 options are always padded to a whole number of 32-bit words. Walking the option-type grammar is deliberately out of scope.

## Awkward edges

The parser is strict about what it will decode. A buffer shorter than 20 bytes, a version byte that is not `4`, an IHL below 5 or above 15, or a header length that exceeds the buffer all yield `INVALID_PARSE` rather than a partial result. The protocol-name table is intentionally small; any protocol number not in `PROTOCOL_NUMBERS` is reported as `"unknown"` rather than guessed.
