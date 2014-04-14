CXX = c++
CXXFLAGS ?= -Wall -Wextra -pedantic -O2
LDFLAGS += -lcrypto -lssl
PREFIX = /usr/local

PROGRAMS = titus
OBJFILES = child.o common.o dh.o titus.o

all: $(PROGRAMS)

titus: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBMILTER_LDFLAGS)

clean:
	rm -f *.o $(PROGRAMS)

install:
	install -m 755 $(PROGRAMS) $(DESTDIR)$(PREFIX)/bin/

.PHONY: all clean install
