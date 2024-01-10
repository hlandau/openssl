# To run the demos when linked with a shared library (default) ensure that
# libcrypto and libssl are on the library path. For example to run the
# ddd-server-fork demo:
#
#    LD_LIBRARY_PATH=../../.. ./ddd-server-fork
#
# You can do this easily with the following command, assuming you are running
# these demos from an OpenSSL worktree which has finished building:
#
#    make run-ddd-server-fork
#
# Building the libuv demos requires the libuv library and header file.  On
# Ubuntu, they are provided by the package "libuv1-dev".

MAKEFLAGS+=-R
PLATFORM=
ifeq ($(PLATFORM),win32)
	EXE=.exe
else
	EXE=
endif

TESTS_BASE =
ifneq ($(PLATFORM),win32)
TESTS_BASE := $(TESTS_BASE) \
    ddd-server-fork-tls \
	ddd-server-prefork-tls
endif
TESTS_BASE := $(TESTS_BASE) \
	ddd-server-mt-tls \
	ddd-server-mt-quic \
	ddd-server-async-pollable-tls \
	ddd-server-async-pollable-quic \
	ddd-server-async-nonpollable-tls \
	ddd-server-async-nonpollable-quic \
	ddd-server-async-unaddressed-tls \
	ddd-server-async-unaddressed-quic \
	ddd-server-dtls-tls \
	ddd-server-dtls-quic

BASE_DIR		= ../../..
INCLUDE			= -I$(BASE_DIR)/include
TESTS			= $(TESTS_BASE)
CFLAGS  		= $(INCLUDE) -g -Og -Wall -Wsign-compare -Wno-unused-function -MD
LDFLAGS 		= -L$(BASE_DIR)
LDLIBS  		= -lcrypto -lssl -luv

ifeq ($(PLATFORM),win32)
LDLIBS			+= -lws2_32
endif

CC_CMD 			= $(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" $(LDLIBS)
VALGRIND		= valgrind
VALGRIND_ARGS	= --leak-check=full

SERVER_CERT		= $(BASE_DIR)/test/certs/servercert.pem
SERVER_KEY		= $(BASE_DIR)/test/certs/serverkey.pem
PORT			= 1111
DEMO_ARGS		= "$(SERVER_CERT)" "$(SERVER_KEY)" "$(PORT)"

.PHONY: all clean

all: $(TESTS)

clean:
	rm -f $(TESTS) *.o *.d *.exe

run-ddd-%: ddd-%$(EXE)
	LD_LIBRARY_PATH="$(BASE_DIR)" ./"$<" $(DEMO_ARGS)

vrun-ddd-%: ddd-%$(EXE)
	LD_LIBRARY_PATH="$(BASE_DIR)" $(VALGRIND) $(VALGRIND_ARGS) -- \
	  ./"$<" $(DEMO_ARGS)

ddd-server-fork-tls$(EXE): ddd-server-fork.c
	$(CC_CMD)

ddd-server-prefork-tls$(EXE): ddd-server-prefork.c
	$(CC_CMD)

ddd-server-mt-tls$(EXE): ddd-server-mt.c
	$(CC_CMD) $(UV_LIBS)

ddd-server-mt-quic$(EXE): ddd-server-mt.c
	$(CC_CMD) $(UV_LIBS) -DUSE_QUIC

ddd-server-async-pollable-tls$(EXE): ddd-server-async-pollable.c
	$(CC_CMD) $(UV_LIBS) -DADDRESSED=1

ddd-server-async-pollable-quic$(EXE): ddd-server-async-pollable.c
	$(CC_CMD) $(UV_LIBS) -DADDRESSED=1 -DUSE_QUIC

ddd-server-async-nonpollable-tls$(EXE): ddd-server-async-nonpollable.c
	$(CC_CMD) $(UV_LIBS) -DADDRESSED=1

ddd-server-async-nonpollable-quic$(EXE): ddd-server-async-nonpollable.c
	$(CC_CMD) $(UV_LIBS) -DADDRESSED=1 -DUSE_QUIC

ddd-server-async-unaddressed-tls$(EXE): ddd-server-async-nonpollable.c
	$(CC_CMD) $(UV_LIBS) -DADDRESSED=0

ddd-server-async-unaddressed-quic$(EXE): ddd-server-async-nonpollable.c
	$(CC_CMD) $(UV_LIBS) -DADDRESSED=0 -DUSE_QUIC

ddd-server-dtls-tls$(EXE): ddd-server-dtls.c
	$(CC_CMD) $(UV_LIBS)

ddd-server-dtls-quic$(EXE): ddd-server-dtls.c
	$(CC_CMD) $(UV_LIBS) -DUSE_QUIC

-include *.d
