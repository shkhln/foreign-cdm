LINUX_CC_BIN   ?= /compat/linux/opt/rh/devtoolset-11/root/usr/bin
LINUX_CC       ?= $(LINUX_CC_BIN)/gcc
LINUX_CFLAGS   ?= -Wall -Wextra -Wno-unused-parameter -B$(LINUX_CC_BIN) --sysroot=/compat/linux -O2 -std=c99
LINUX_CXXFLAGS ?= -Wall -Wextra -Wno-unused-parameter -B$(LINUX_CC_BIN) --sysroot=/compat/linux -O2 -std=c++17
CFLAGS         += -Wall -Wextra -Wno-unused-parameter
MAKE_JOBS_NUMBER ?= 1

.PHONY: all fcdm lcdm util clean clean-all

fcdm: build/fcdm-fbsd.so build/fcdm-worker build/fcdm-jail
lcdm: build/fcdm-linux.so
util: build/override-fbsd.so build/override-linux.so

all: fcdm lcdm util

build/fcdm-fbsd.so: src/config.h src/lib.cpp src/util.h src/cdm.capnp.h build/capnp-fbsd
	mkdir -p build
	$(CXX) $(CXXFLAGS) -std=c++17 -DKJ_DEBUG -Ithird_party -Ithird_party/capnproto/c++/src -fPIC -shared -o $(.TARGET) \
 -Wl,--whole-archive \
 build/capnp-fbsd/c++/src/capnp/libcapnpc.a \
 build/capnp-fbsd/c++/src/capnp/libcapnp-rpc.a \
 build/capnp-fbsd/c++/src/capnp/libcapnp.a \
 build/capnp-fbsd/c++/src/kj/libkj-async.a \
 build/capnp-fbsd/c++/src/kj/libkj.a \
 -Wl,--no-whole-archive \
 src/cdm.capnp.c++ \
 src/lib.cpp \
 -pthread

build/fcdm-linux.so: src/config.h src/lib.cpp src/util.h src/cdm.capnp.h build/capnp-linux
	mkdir -p build
	${LINUX_CC:S|gcc$|g++|} $(LINUX_CXXFLAGS) -DKJ_DEBUG -Ithird_party -Ithird_party/capnproto/c++/src -fPIC -shared -o $(.TARGET) \
 -Wl,--whole-archive \
 build/capnp-linux/c++/src/capnp/libcapnpc.a \
 build/capnp-linux/c++/src/capnp/libcapnp-rpc.a \
 build/capnp-linux/c++/src/capnp/libcapnp.a \
 build/capnp-linux/c++/src/kj/libkj-async.a \
 build/capnp-linux/c++/src/kj/libkj.a \
 -Wl,--no-whole-archive \
 src/cdm.capnp.c++ \
 src/lib.cpp \
 -pthread -ldl

build/fcdm-worker: src/config.h src/worker.cpp src/util.h src/cdm.capnp.h build/capnp-linux
	mkdir -p build
	${LINUX_CC:S|gcc$|g++|} $(LINUX_CXXFLAGS) -DKJ_DEBUG -Ithird_party -Ithird_party/capnproto/c++/src -o $(.TARGET) \
 -Wl,--whole-archive \
 build/capnp-linux/c++/src/capnp/libcapnpc.a \
 build/capnp-linux/c++/src/capnp/libcapnp-rpc.a \
 build/capnp-linux/c++/src/capnp/libcapnp.a \
 build/capnp-linux/c++/src/kj/libkj-async.a \
 build/capnp-linux/c++/src/kj/libkj.a \
 -Wl,--no-whole-archive \
 src/cdm.capnp.c++ \
 src/worker.cpp \
 -pthread -ldl && chmod a+x $(.TARGET)

build/fcdm-jail: src/config.h src/jail.c
	mkdir -p build
	$(CC) $(CFLAGS) -ljail -lutil -o $(.TARGET) src/jail.c && chmod a+srX $(.TARGET)

build/override-fbsd.so: src/override.c
	mkdir -p build
	$(CC) $(CFLAGS) -fPIC -shared -o $(.TARGET) src/override.c && chmod a+rX $(.TARGET)

build/override-linux.so: src/override.c
	mkdir -p build
	${LINUX_CC:S|g++$|gcc|} $(LINUX_CFLAGS) -fPIC -shared -o $(.TARGET) src/override.c -ldl && chmod a+rX $(.TARGET)

src/cdm.capnp.h: src/cdm.capnp build/capnp-fbsd
	./build/capnp-fbsd/c++/src/capnp/capnp compile -obuild/capnp-fbsd/c++/src/capnp/capnpc-c++ src/cdm.capnp

build/capnp-fbsd:
	mkdir -p build/capnp-fbsd
	env CXXFLAGS="$(CXXFLAGS) -include 'netinet/in.h' -fPIC" cmake -S third_party/capnproto -B $(.TARGET) \
 -DWITH_ZLIB=OFF -DWITH_OPENSSL=OFF -DWITH_FIBERS=OFF -DBUILD_TESTING=OFF
	make -C build/capnp-fbsd -j${MAKE_JOBS_NUMBER}

build/capnp-linux:
	mkdir -p build/capnp-linux
	env CXX="${LINUX_CC:S|gcc$|g++|}" CXXFLAGS="$(LINUX_CXXFLAGS) -fPIC" cmake -S third_party/capnproto -B $(.TARGET) \
 -DWITH_ZLIB=OFF -DWITH_OPENSSL=OFF -DWITH_FIBERS=ON -DBUILD_TESTING=OFF
	make -C build/capnp-linux -j${MAKE_JOBS_NUMBER}

clean:
	rm -f src/cdm.capnp.h
	rm -f src/cdm.capnp.c++
	rm -f build/fcdm-fbsd.so
	rm -f build/fcdm-linux.so
	rm -f build/fcdm-worker
	rm -f build/fcdm-jail
	rm -f build/override-fbsd.so
	rm -f build/override-linux.so

clean-all: clean
	rm -rf build/capnp-fbsd
	rm -rf build/capnp-linux
