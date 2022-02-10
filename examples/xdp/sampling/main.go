// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/dropbox/goebpf"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var configInt = flag.String("configInt", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "ebpf_prog/xdp.elf", "clang/llvm compiled binary file")

const metadataSize = 4

type metadata struct {
	Cookie uint16
	PktLen uint16
}

func main() {
	flag.Parse()

	if *configInt == "" {
		fatalError("-configInt is required.")
	}

	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Find protocols eBPF map
	samplePacketMap := bpf.GetMapByName("sample_packet")
	if samplePacketMap == nil {
		fatalError("eBPF map 'sample_packet' not found")
	}

	// Program name matches function name in xdp.c:
	//      int xdp_sample_prog(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName("xdp_sample_prog")
	if xdp == nil {
		fatalError("Program 'xdp_sample_prog' not found.")
	}

	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*configInt)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}

	// Start listening to Perf Events
	perf, _ := goebpf.NewPerfEvents(samplePacketMap)
	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		fatalError("perf.StartForAllProcessesAndCPUs(): %v", err)
	}

	// Print stat every second / exit on CTRL+C
	fmt.Println("XDP program successfully loaded and attached.")
	fmt.Println()

	go func() {
		var meta metadata
		for {
			if eventData, ok := <-perfEvents; ok {
				reader := bytes.NewReader(eventData)
				binary.Read(reader, binary.LittleEndian, &meta)
				fmt.Printf("%+v, %+v", ntohs(meta.Cookie), ntohs(meta.PktLen))
				if len(eventData)-metadataSize > 0 {
					// event contains packet sample as well
					fmt.Println(hex.Dump(eventData[metadataSize:]))
				}
			} else {
				// Update channel closed
				break
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)

	// graceful quit signal
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigchan

		perf.Stop()
		fmt.Println("\nSummary:")
		fmt.Printf("\t%d Event(s) Received\n", perf.EventsReceived)
		fmt.Printf("\t%d Event(s) lost (e.g. small buffer, delays in processing)\n", perf.EventsLost)
		fmt.Println("\nDetaching program and exit...")

		log.Printf("detach")
		if err := xdp.Detach(); err != nil {
			log.Printf("detach with err: %+v", err)
			log.Printf("need to xdp-load manually")
		}
		wg.Done()
	}()

	wg.Wait()
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8) | (value >> 8)
}
