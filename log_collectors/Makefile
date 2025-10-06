APXS ?= apxs
CC   ?= $(shell $(APXS) -q CC)
CFLAGS_EXTRA ?=
HIREDIS_CFLAGS ?= $(shell pkg-config --cflags hiredis 2>/dev/null || echo -I/usr/include/hiredis)
HIREDIS_LDFLAGS ?= $(shell pkg-config --libs hiredis 2>/dev/null || echo -lhiredis)

SRC  = mod_ualog.c
OBJ  = mod_ualog.lo
LA   = .libs/mod_ualog.so

all: build

build:
	$(APXS) -c $(CFLAGS_EXTRA) $(HIREDIS_CFLAGS) $(HIREDIS_LDFLAGS) $(SRC)

install: build
	$(APXS) -i mod_ualog.la

enable:
	@echo "Add this to your Apache config if not present:"
	@echo "LoadModule ualoglog_module $$( $(APXS) -q LIBEXECDIR )/mod_ualog.so"

clean:
	@rm -rf .libs *.o *.la *.lo *.slo *.la *.lo *.o *.a

rebuild: clean all

.PHONY: all build install enable clean rebuild

