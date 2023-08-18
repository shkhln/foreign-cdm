
LINUX_CC       ?= /compat/linux/opt/rh/devtoolset-9/root/usr/bin/g++
LINUX_CXXFLAGS ?= --sysroot=/compat/linux -std=c++17 -Wall -Wextra -Wno-unused-parameter # TODO: remove -Wno-unused-parameter

all: build/fcdm-linux.so build/fcdm-worker # build/fcdm-fbsd.so

build/fcdm-fbsd.so: src/config.h src/lib.cpp src/util.h src/cdm.capnp.h build/capnp-fbsd
	mkdir -p build
	$(CC) $(CXXFLAGS) -DKJ_DEBUG -Ithird_party -Ithird_party/capnproto/c++/src -fPIC -shared -o $(.TARGET) \
 -Wl,--whole-archive \
 build/capnp-fbsd/c++/src/capnp/libcapnpc.a \
 build/capnp-fbsd/c++/src/capnp/libcapnp-rpc.a \
 build/capnp-fbsd/c++/src/capnp/libcapnp.a \
 build/capnp-fbsd/c++/src/kj/libkj-async.a \
 build/capnp-fbsd/c++/src/kj/libkj.a \
 -Wl,--no-whole-archive \
 src/cdm.capnp.c++ \
 src/lib.cpp \
 -pthread && chmod -R o+rX build

build/fcdm-linux.so: src/config.h src/lib.cpp src/util.h src/cdm.capnp.h build/capnp-linux
	mkdir -p build
	$(LINUX_CC) $(LINUX_CXXFLAGS) -DKJ_DEBUG -Ithird_party -Ithird_party/capnproto/c++/src -fPIC -shared -o $(.TARGET) \
 -Wl,--whole-archive \
 build/capnp-linux/c++/src/capnp/libcapnpc.a \
 build/capnp-linux/c++/src/capnp/libcapnp-rpc.a \
 build/capnp-linux/c++/src/capnp/libcapnp.a \
 build/capnp-linux/c++/src/kj/libkj-async.a \
 build/capnp-linux/c++/src/kj/libkj.a \
 -Wl,--no-whole-archive \
 src/cdm.capnp.c++ \
 src/lib.cpp \
 -pthread -ldl && chmod -R o+rX build

build/fcdm-worker: src/config.h src/worker.cpp src/util.h src/cdm.capnp.h build/capnp-linux
	mkdir -p build
	$(LINUX_CC) $(LINUX_CXXFLAGS) -DKJ_DEBUG -Ithird_party -Ithird_party/capnproto/c++/src -o $(.TARGET) \
 -Wl,--whole-archive \
 build/capnp-linux/c++/src/capnp/libcapnpc.a \
 build/capnp-linux/c++/src/capnp/libcapnp-rpc.a \
 build/capnp-linux/c++/src/capnp/libcapnp.a \
 build/capnp-linux/c++/src/kj/libkj-async.a \
 build/capnp-linux/c++/src/kj/libkj.a \
 -Wl,--no-whole-archive \
 src/cdm.capnp.c++ \
 src/worker.cpp \
 -pthread -ldl && chmod -R o+rX build

src/cdm.capnp.h: src/cdm.capnp build/capnp-linux
	./build/capnp-linux/c++/src/capnp/capnp compile -obuild/capnp-linux/c++/src/capnp/capnpc-c++ src/cdm.capnp

build/capnp-fbsd:
	mkdir -p build/capnp-fbsd
	env CXXFLAGS="$(CXXFLAGS) -include 'netinet/in.h' -fPIC" cmake -S third_party/capnproto -B $(.TARGET) -DWITH_ZLIB=OFF -DWITH_OPENSSL=OFF -DWITH_FIBERS=OFF
	make -C build/capnp-fbsd

build/capnp-linux:
	mkdir -p build/capnp-linux
	env CXX="$(LINUX_CC)" CXXFLAGS="$(LINUX_CXXFLAGS) -fPIC" cmake -S third_party/capnproto -B $(.TARGET) -DWITH_ZLIB=OFF -DWITH_OPENSSL=OFF -DWITH_FIBERS=ON
	make -C build/capnp-linux

clean:
	rm -f src/cdm.capnp.h
	rm -f src/cdm.capnp.c++
	rm -f build/fcdm-fbsd.so
	rm -f build/fcdm-linux.so
	rm -f build/fcdm-worker

clean-all: clean
	rm -f capnp-fbsd
	rm -f capnp-linux
