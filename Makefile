CC ?= cc
PYTHON ?= python3
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -D_GNU_SOURCE
LDLIBS += -lm
PREFIX ?= /usr/local

all: dvb-mux
dvb-mux: main.c json.c json.h eit_forward.c eit_forward.h
	$(CC) $(CPPFLAGS) $(CFLAGS) main.c json.c eit_forward.c $(LDFLAGS) $(LDLIBS) -o $@

test: dvb-mux
	$(PYTHON) tests/dvb_mux_test.py --binary ./dvb-mux
	./dvb-mux --config examples/two-channels.json --check-config

install: dvb-mux
	install -Dm755 dvb-mux $(DESTDIR)$(PREFIX)/bin/dvb-mux
	install -Dm644 LICENSE $(DESTDIR)$(PREFIX)/share/doc/dvb-mux/LICENSE
	install -Dm644 README.md $(DESTDIR)$(PREFIX)/share/doc/dvb-mux/README.md
	install -Dm644 PROVENANCE.md $(DESTDIR)$(PREFIX)/share/doc/dvb-mux/PROVENANCE.md
	install -Dm644 docs/configuration.md $(DESTDIR)$(PREFIX)/share/doc/dvb-mux/docs/configuration.md
	install -Dm644 examples/two-channels.json $(DESTDIR)$(PREFIX)/share/doc/dvb-mux/examples/two-channels.json

clean:
	rm -f dvb-mux
.PHONY: all clean install test
