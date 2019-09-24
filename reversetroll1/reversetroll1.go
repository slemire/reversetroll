package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cakturk/go-netstat/netstat"
)

var (
	interval = flag.Int("interval", 60, "interval between checks")
	port     = flag.Int("port", 4444, "TCP port to connect back to")
	help     = flag.Bool("help", false, "display this help screen")

	message = `
Microsoft Windows [Version 10.0.16299.1331]
(c) 2017 Microsoft Corporation. All rights reserved.

C:\Windows\System32>`
)

func main() {
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	fmt.Println("[+] Get ready to troll! Snowscan / 2019")

	var fn netstat.AcceptFn
	var clients []string
	fn = func(*netstat.SockTabEntry) bool { return true }

	for {
		tabs, err := netstat.TCPSocks(fn)
		if err == nil {
			clients = getSockInfo("tcp", tabs)
		}
		fmt.Println("Clients to send a troll reverse shell to:")
		fmt.Println("-----------------------------------------")
		fmt.Println(strings.Join(clients, "\n"))
		for _, ip := range clients {
			sendFakeShell(ip, *port)
		}
		fmt.Printf("Sleeping for %d seconds\n", *interval)
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

func getSockInfo(proto string, s []netstat.SockTabEntry) (keys []string) {
	lookup := func(skaddr *netstat.SockAddr) string {
		const IPv4Strlen = 17
		addr := skaddr.IP.String()
		return addr
	}

	// Create set with source IP addresses
	set := make(map[string]bool)
	for _, e := range s {
		daddr := lookup(e.RemoteAddr)
		// Only match IP addresses in the 10.0.0.0/8 CIDR block
		match, _ := regexp.MatchString(`^10\.\d{1,3}\.\d{1,3}\.\d{1,3}`, daddr)
		if match {
			set[daddr] = true
		}
	}

	// Build array with unique IP addresses
	for key := range set {
		keys = append(keys, key)
	}

	return keys
}

func sendFakeShell(ip string, port int) {
	host := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", host, 1*time.Second)
	if err == nil {
		fmt.Printf("Sent a fake shell to %s!\n", host)
		fmt.Fprintf(conn, message)
		buffer := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		conn.Read(buffer)
		conn.Close()
	}
}
