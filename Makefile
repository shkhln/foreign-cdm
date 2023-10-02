
LINUX_CC       ?= /compat/linux/opt/rh/devtoolset-9/root/usr/bin/g++
LINUX_CXXFLAGS ?= -Wall -Wextra -Wno-unused-parameter -O2 -std=c++17 --sysroot=/compat/linux
CFLAGS         += -Wall -Wextra -Wno-unused-parameter
MAKE_JOBS_NUMBER ?= 1

all: build/fcdm-fbsd.so build/fcdm-worker build/fcdm-jail build/fcdm-cleanup

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
 -pthread && chmod a+rX $(.TARGET)

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
 -pthread -ldl && chmod a+rX $(.TARGET)

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
 -pthread -ldl && chmod a+rX $(.TARGET)

build/fcdm-jail: src/config.h src/jail.c
	mkdir -p build
	$(CC) $(CFLAGS) -ljail -o $(.TARGET) src/jail.c && chmod a+srX $(.TARGET)

build/fcdm-cleanup: src/config.h src/cleanup.c
	mkdir -p build
	$(CC) $(CFLAGS) -o $(.TARGET) src/cleanup.c && chmod a+srX $(.TARGET)

src/cdm.capnp.h: src/cdm.capnp build/capnp-fbsd
	./build/capnp-fbsd/c++/src/capnp/capnp compile -obuild/capnp-fbsd/c++/src/capnp/capnpc-c++ src/cdm.capnp

build/capnp-fbsd:
	mkdir -p build/capnp-fbsd
	env CXXFLAGS="$(CXXFLAGS) -include 'netinet/in.h' -fPIC" cmake -S third_party/capnproto -B $(.TARGET) -DWITH_ZLIB=OFF -DWITH_OPENSSL=OFF -DWITH_FIBERS=OFF -DBUILD_TESTING=OFF
	make -C build/capnp-fbsd -j${MAKE_JOBS_NUMBER}

build/capnp-linux:
	mkdir -p build/capnp-linux
	env CXX="$(LINUX_CC)" CXXFLAGS="$(LINUX_CXXFLAGS) -fPIC" cmake -S third_party/capnproto -B $(.TARGET) -DWITH_ZLIB=OFF -DWITH_OPENSSL=OFF -DWITH_FIBERS=ON -DBUILD_TESTING=OFF
	make -C build/capnp-linux -j${MAKE_JOBS_NUMBER}

clean:
	rm -f src/cdm.capnp.h
	rm -f src/cdm.capnp.c++
	rm -f build/fcdm-fbsd.so
	rm -f build/fcdm-linux.so
	rm -f build/fcdm-worker

clean-all: clean
	rm -f capnp-fbsd
	rm -f capnp-linux
