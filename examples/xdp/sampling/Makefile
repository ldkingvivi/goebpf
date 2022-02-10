# Copyright (c) 2019 Dropbox, Inc.
# Full license can be found in the LICENSE file.

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I../../..

GO_SOURCE := main.go
GO_BINARY := main

EBPF_SOURCE := ebpf_prog/xdp.c
EBPF_BINARY := ebpf_prog/xdp.elf
EBPF_O := ebpf_prog/xdp.o


all: build_bpf build_o build_go

build_bpf: $(EBPF_BINARY)

build_o: $(EBPF_O)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)
	rm -f $(EBPF_O)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

$(EBPF_O): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@
