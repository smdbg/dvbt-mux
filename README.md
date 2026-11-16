# DVB-T Mux

A standalone Linux MPEG-TS VBR multiplexer written in C. It combines selected
services from IPv4 UDP or MPEG-TS RTP/UDP inputs into one transport stream on
standard output, for example to feed a USB DVB-T modulator.

The repository is named **dvbt-mux**; the installed executable is **dvb-mux**.
It uses no FFmpeg, TSDuck, MPTSD, Python runtime or container. Python 3 is needed
only for the optional tests. There is no audio/video decoding or transcoding.

```text
UDP / RTP inputs → dvb-mux → raw MPEG-TS stdout → transmitter or file
```

## Features

- Up to 64 selected services, including multiple services from the same input.
- Automatic output PID allocation, with rewritten PMT/CAT CA references.
- PAT, PMT, CAT, SDT, terrestrial NIT, EACEM LCN, TDT and TOT generation.
- EPG passthrough: event text, language codes and encoding selectors remain
  unchanged; EIT service/network identifiers and CRC are updated.
- Clear and already scrambled services; ECM/EMM passthrough and optional shared
  EMM deduplication. The mux itself does not encrypt or decrypt content.
- A bounded RAM queue, batched UDP reception and batched output writes.
- VBR output without software NULL stuffing; input NULL packets are removed.
- Optional JSON counters sampled approximately every ten seconds.

## Build and install

Linux with a C11 compiler, GNU make and glibc (including iconv) is the supported
build environment. Only libc and libm are linked; libusb belongs to the separate
transmitter. Linux `recvmmsg` is required.

On Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y git build-essential python3
git clone https://github.com/smdbg/dvbt-mux.git
cd dvbt-mux
make -j"$(nproc)"
make test
sudo make install
```

`make test` uses synthetic local UDP streams; it needs no DVB or USB hardware.
To run without installation, use `./dvb-mux` from this directory.
The default prefix is `/usr/local`; `PREFIX` and `DESTDIR` are supported:

```bash
make install PREFIX="$HOME/.local"
```

## Configure two channels

Start with [examples/two-channels.json](examples/two-channels.json):

```bash
cp examples/two-channels.json mux.json
# Edit mux.json to match your inputs, services and DVB-T parameters.
dvb-mux --config mux.json --check-config
```

The example receives `239.10.0.1:1234` and `239.10.0.2:1234` and assigns output
service IDs and LCNs 1 and 2. It describes 474 MHz, 8 MHz, 64-QAM, FEC 3/4,
guard 1/32 and 8K in the NIT. These are example values, not hardware defaults
that are automatically applied to a transmitter.

For each input:

- `url` is `udp://IPv4:port`. Both raw TS and RTP-wrapped TS are accepted on that
  socket. DNS names, HTTP/HLS and IPv6 are not supported directly.
- `interface` is the local IPv4 address used for multicast membership;
  `0.0.0.0` lets the kernel select it. For a local loopback multicast source,
  use `127.0.0.1` and ensure the sender also uses loopback.
- `input_service_id` selects the input program. `0` selects the first nonzero
  program from its PAT. Set an explicit SID when receiving a multiprogram TS.
- `service_id` and `lcn` are the output identifiers. SIDs and nonzero LCNs must
  be unique in the mux. LCN 0 omits that service's LCN entry.
- `scrambled` sets the SDT indication; it does not scramble the packets.

Input JSON is always UTF-8. `codepage` selects the encoding of generated names:
`ISO-6937`, `ISO-8859-5` or `UTF-8`. EPG descriptors pass through unchanged.
The example's `BGR` and UTC offset `120` are illustrative; select your location
and current offset. Daylight-saving changes are not calculated automatically.

See [the complete configuration reference](docs/configuration.md) for field
limits, multiple transports in one NIT, shared EMM and telemetry.

## Run without hardware

Write a short capture while your configured UDP sources are running:

```bash
timeout --signal=TERM 20s dvb-mux --config mux.json > capture.ts
```

`timeout` normally returns 124 when its deadline ends. Output is a raw 188-byte
MPEG-TS stream; diagnostics go to stderr. Do not write TS stdout to a terminal.

## Feed an IT9507 / UT-100C modulator

Build and install [sendts-it9507](https://github.com/smdbg/sendts-it9507)
separately, configure its USB permissions, and obtain its serial with
`sendts-it9507 --list`. Run the following in Bash, replacing `YOUR_USB_SERIAL`:

```bash
set -o pipefail
dvb-mux --config mux.json --status-file /tmp/dvbt-mux-status.json |
  sendts-it9507 --transmit --serial YOUR_USB_SERIAL \
    -f 474000 -b 8000 -t 8k -C qam64 -r 3/4 -G 1/32 -g -10
```

Only `sendts-it9507` opens USB and enables RF. Both programs are ordinary
processes connected by a RAM pipe. Ctrl+C stops the foreground pipeline.
If supervising them individually, stop the transmitter first and then the mux;
there is no process supervisor built into `dvb-mux`.

Keep the transmitter parameters and JSON RF fields consistent. This example
has a payload capacity of approximately **27.144 Mbps**. `capacity_bps` is for
reporting occupancy, not rate shaping: leave headroom for bitrate peaks and SI.
VBR output requires a consumer that accepts it; the tested UT-100C does.

Read counters without opening another stream receiver:

```bash
python3 -m json.tool /tmp/dvbt-mux-status.json
```

## Limits and operation

The mux preserves the original per-service PCR/PTS/DTS timeline. It does not
restamp PCR, synchronize independent encoder clocks, generate CBR NULL packets
or reduce codec bitrate. A slow consumer can fill the RAM queue; excess packets
are dropped and counted. Long-term input bitrate must fit the output capacity.
Configuration is read at startup; restart after editing it.

The NIT is DVB-T and the LCN format is EACEM. Receiver LCN support depends on the
receiver's scanning profile. This program does not generate DVB-C delivery
information or DVB-T2 signaling.

UDP sources must repeat PAT/PMT; scrambled sources must also supply the relevant
CAT/ECM/EMM. Missing or malformed input tables are reported on stderr. Silence
is visible in the active-service counters, and UDP reception resumes when the
source returns. Counter history is not stored by the program.

## Tests and provenance

`make test` exercises local UDP inputs and independently parses the output:
PID collision remapping, common CAT and shared EMM, EPG preservation, text
encodings, continuity, NULL removal, shared unicast inputs and multi-section NIT.

For a sanitizer build:

```bash
make clean
make CFLAGS='-O1 -g -std=c11 -Wall -Wextra -D_GNU_SOURCE -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined'
make test
```

The mux and JSON reader are GPL-2.0-only. The included EIT forwarding module is
GPL-2.0-or-later. See [LICENSE](LICENSE) and [PROVENANCE.md](PROVENANCE.md).
