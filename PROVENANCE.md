# Source provenance

Standalone extraction on 2026-11-16 from the headend project at
https://git.promet.ad/mitev/tsdecrypt, revision
`525d6cca6a23db65213ad6929ca664059de74a11`:

- `tools/dvb-mux/`: native mux, bounded JSON reader, EIT module and build files.
- `tests/dvb_mux_test.py`: independent black-box UDP/MPEG-TS regression tests.

The native mux and JSON reader were developed for that headend and are licensed
GPL-2.0-only. `eit_forward.c` and `eit_forward.h` were brought over from the EIT
forwarding module in our modified MPTSD tree (`third_party/mptsd`), licensed
GPL-2.0-or-later. Their existing notices are retained. This does not introduce
a runtime or build dependency on MPTSD or tsdecrypt.

Standalone packaging adapts test paths, installation, examples and documentation.
The packet-processing implementation is unchanged from the source revision above.
The repository name is `dvbt-mux`; the executable remains `dvb-mux`.
