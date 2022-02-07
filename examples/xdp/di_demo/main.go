// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/dropbox/goebpf"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
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

	// Print stat every second / exit on CTRL+C
	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-ticker.C:
				fmt.Println("Action                 Counts")
				dropCount, err := packetActionCount.LookupUint64(goebpf.XdpDrop)
				if err != nil {
					log.Printf("drop count err: %+v", err)
					continue
				}
				fmt.Printf("XDPDrop:    %d\n", dropCount)

				passCount, err := packetActionCount.LookupUint64(2)
				if err != nil {
					log.Printf("pass count err: %+v", err)
					continue
				}
				fmt.Printf("XDPPass:    %d\n", passCount)

				fmt.Println()
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
