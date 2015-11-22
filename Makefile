CXXFLAGS ?= -Wall -Wextra -pedantic -O2
CXXFLAGS += -std=c++11
LDFLAGS += -lcrypto -lssl
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

PROGRAMS = titus
MANPAGES = titus.8
OBJFILES = child.o common.o util.o dh.o keyserver.o rsa_client.o rsa_server.o titus.o

all: $(PROGRAMS)

titus: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJFILES) $(LDFLAGS)

clean:
	rm -f *.o $(PROGRAMS)

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(PROGRAMS) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 $(MANPAGES) $(DESTDIR)$(MANDIR)/

.PHONY: all clean install
