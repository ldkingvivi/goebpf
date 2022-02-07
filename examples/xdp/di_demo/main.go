// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dropbox/goebpf"
)

var configInt = flag.String("configInt", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "ebpf_prog/xdp.elf", "clang/llvm compiled binary file")
var ipList ipAddressList

func main() {
	flag.Var(&ipList, "drop", "IPv4 CIDR to DROP traffic from, repeatable")
	flag.Parse()

	if *configInt == "" {
		fatalError("-configInt is required.")
	}

	if len(ipList) == 0 {
		fatalError("at least one IPv4 address to DROP required (-drop)")
	}

	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Find protocols eBPF map
	packetActionCount := bpf.GetMapByName("action_count")
	if packetActionCount == nil {
		fatalError("eBPF map 'action_count' not found")
	}

	denyIPs := bpf.GetMapByName("deny_ip_list")
	if denyIPs == nil {
		fatalError("eBPF map 'deny_ip_list' not found")
	}

	// Program name matches function name in xdp.c:
	//      int packet_drop(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName("packet_drop")
	if xdp == nil {
		fatalError("Program 'packet_drop' not found.")
	}

	// Populate eBPF map with IPv4 addresses to block
	fmt.Println("deny IPv4 addresses...")
	for index, ip := range ipList {
		fmt.Printf("\t%s\n", ip)
		err := denyIPs.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	fmt.Println()

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
	defer xdp.Detach()

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Print stat every second / exit on CTRL+C
	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println()
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			fmt.Println("IP                 DROPs")
			for i := 1; i < 3; i++ {
				value, err := packetActionCount.LookupUint64(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}
				fmt.Printf("%d    %d\n", i, value)
			}
			fmt.Println()
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
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

type ipAddressList []string

func (i *ipAddressList) String() string {
	return fmt.Sprintf("%+v", *i)
}

func (i *ipAddressList) Set(value string) error {
	if len(*i) == 1024 {
		return errors.New("up to 1024 IPv4 addresses supported")
	}
	// Validate that value is correct IPv4 address
	if !strings.Contains(value, "/") {
		value += "/32"
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s is not an IPv4 address", value)
	}
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	// Valid, add to the list
	*i = append(*i, value)
	return nil
}
