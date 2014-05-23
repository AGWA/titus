CXX = c++
CXXFLAGS ?= -Wall -Wextra -pedantic -O2
LDFLAGS += -lcrypto -lssl
PREFIX = /usr/local

PROGRAMS = titus
MANPAGES = titus.8
OBJFILES = child.o common.o util.o dh.o rsa_client.o rsa_server.o titus.o

all: $(PROGRAMS)

titus: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(PROGRAMS)

install:
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(PROGRAMS) $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/share/man
	install -m 644 $(MANPAGES) $(DESTDIR)$(PREFIX)/share/man/

.PHONY: all clean install
