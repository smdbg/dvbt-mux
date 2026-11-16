# Configuration reference

```json
{
  "network_id": 1,
  "network_name": "DVB Headend",
  "provider_name": "DVB Headend",
  "transport_stream_id": 1,
  "original_network_id": 1,
  "country": "BGR",
  "utc_offset_minutes": 120,
  "codepage": "UTF-8",
  "frequency_khz": 474000,
  "bandwidth_mhz": 8,
  "modulation": "64-QAM",
  "fec": "3/4",
  "guard": "1/32",
  "transmission_mode": "8K",
  "capacity_bps": 27144384,
  "buffer_bytes": 8388608,
  "version": 0,
  "inputs": [
    {
      "id": "channel-1",
      "url": "udp://238.0.3.1:1234",
      "interface": "127.0.0.1",
      "input_service_id": 201,
      "service_id": 1,
      "name": "Channel 1",
      "service_type": 1,
      "lcn": 1,
      "scrambled": false
    }
  ]
}
```

`input_service_id: 0` selects the first nonzero program in a complete input PAT.
Each input can override `provider_name`. Up to 64 configured services are
supported. SIDs and nonzero LCNs must be unique. LCN 0 omits that entry. JSON
configuration strings always use UTF-8. `codepage` selects only the generated
SDT service/provider names and NIT network name:

| Setting | Emitted DVB text |
| --- | --- |
| `UTF-8` (existing default) | Selector `0x15` followed by UTF-8 |
| `ISO-8859-5` | Selector `0x01` followed by ISO-8859-5 Cyrillic text |
| `ISO-6937` | DVB default Latin table, without a selector |

Strict `iconv` conversion happens once when configuration is loaded, not in the
packet loop. DVB's Euro-sign extension (`0xa4`) to ISO 6937 is supported.
Unrepresentable characters, invalid UTF-8 and oversized encoded descriptors are
rejected; there is no transliteration or truncation. The encoded service name
plus provider must occupy at most 252 bytes including any selectors; encoded
network name must occupy at most 255 bytes including its selector. For UTF-8
this leaves 250 raw bytes for service plus provider, and 254 for network name.

**This setting never converts input EPG.** All incoming short-event and
extended-event descriptor text, language codes and their per-string character
selectors pass through byte-for-byte. Changing generated table encoding is a
receiver-compatibility option, not evidence that incoming EIT text was corrupt.

The fixed UTC offset applies to the generated TOT; the application does not
calculate regional daylight-saving changes. RF settings describe terrestrial
NIT; they do not themselves program the USB device. `capacity_bps` is used for
occupancy reporting, not CBR stuffing or automatic transcoding.

Optional `network_transports` lists up to 32 enabled transports in this network.
Each entry carries `transport_stream_id`, `original_network_id`, the RF fields
shown above, and `inputs` containing `{service_id, lcn}` entries. Every mux in
the network can therefore advertise the same terrestrial frequencies and LCNs.
The current transport is included automatically if absent. NIT is split on
transport-entry boundaries when necessary. `network_version` selects its
five-bit version independently of PAT/PMT discovery; use the same version and transport list in each mux instance, and increment
this value modulo 32 when the network configuration changes.

Multiple selected services using the same endpoint and interface share one UDP
socket. Every received datagram is dispatched to their respective service
filters; this also works for unicast, where separate `SO_REUSEADDR` sockets
would otherwise compete for packets.

## PSI/SI and conditional access

The mux generates PAT, rewritten PMTs, a combined CAT, SDT, terrestrial NIT with
EACEM LCN, TDT and TOT. It validates CRCs and descriptor lengths before using
input tables, handles multi-section PAT/CAT, and preserves all PMT descriptors
while rewriting referenced ECM and ES/PCR PIDs. Each source owns a separate
output PID namespace. A conflicting elementary/ECM/EMM role in one input is
rejected; its last coherent PMT/CAT remains active until a compatible update.

Input actual-TS EIT p/f and schedule sections for the selected service are
forwarded without decoding event descriptors. SID, TSID, ONID and CRC are
updated. Other-TS EIT is not relabelled as belonging to this multiplex.

By default every input's EMM PID is independent. An explicitly known common
entitlement feed can set `emm_group`, `emm_caid` and `emm_pid` on each member.
Only matching CA descriptors with identical private data share an output EMM
PID (the first is 8064); CAID equality alone never establishes shared provenance.
One member supplies EMM; after two seconds without EMM a live member can take
over at a payload-unit-start boundary. A common CAT advertises the deduplicated
descriptor. No ECM or EMM payload is decrypted or rewritten.

## Queue limits and telemetry

The output queue defaults to 8 MiB and can be configured from 1 to 64 MiB.
Queue overflow drops new complete packets/sections and increments a counter;
it cannot make an overloaded RF channel carry more payload. Input socket buffers
are bounded independently by the kernel. Datagrams must contain whole 188-byte
TS packets (optionally after an RTP header); malformed traffic is counted.

The status file is atomically replaced approximately every ten seconds, and at
shutdown. It reports output Mbps, capacity, occupancy, packet counts, removed
NULLs, malformed packets, queue peak, drops, errors, configured services,
PMT-ready services and services with media received within ten seconds. Reading
status does not subscribe to another copy of the transport. Numeric occupancy
does not constitute a receiver PCR-jitter or RF quality measurement.

SIGTERM/SIGINT stop the process. The parent must stop its separately owned USB
transmitter as well. Source reconnects happen naturally because the UDP socket
remains joined; source silence is visible as a lack of active services. This
first version does not resample stream clocks or conceal input discontinuities.
