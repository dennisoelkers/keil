package main

import (
	"encoding/json"
	"github.com/fatih/structs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/robertkowalski/graylog-golang"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"strings"
	"time"
	"reflect"
)

var (
	fromFile = kingpin.Flag("file", "Read from file instead of device").Short('f').Bool()
	source = kingpin.Arg("source", "Name of device/filename to read from").Required().String()
	host = kingpin.Flag("host", "Hostname of Graylog server").Default("localhost").Short('h').String()
	port = kingpin.Flag("port", "Port of Graylog Server").Default("12201").Short('p').Int()
)

func getSource(fromFile bool, sourceName string) (*pcap.Handle, error) {
	if (fromFile) {
		return pcap.OpenOffline(sourceName)
	} else {
		return pcap.OpenLive(sourceName, 1500, true, time.Millisecond)
	}
}

func main() {
	var logger = log.New(os.Stdout, "", log.Ldate | log.Ltime | log.Lmicroseconds)
	kingpin.Parse()

	g := gelf.New(gelf.Config{
		GraylogPort:     *port,
		GraylogHostname: *host,
	})

	var sourceName = strings.TrimSpace(*source)

	handle, err := getSource(*fromFile, sourceName)

	if (err != nil) {
		logger.Panic("Error: ", sourceName, err)
	} else {
		logger.Println("Capturing from", sourceName, ", link type: ", handle.LinkType())
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		//logger.Println("Packet: ", packet)

		packetEvent := make(map[string]interface{})
		packetEvent["version"] = "1.0"
		packetEvent["host"] = "localhost"
		packetEvent["timestamp"] = time.Now().UTC().String()
		packetEvent["facility"] = "pflog"
		packetEvent["short_message"] = "pflog"

		if pflogLayer := packet.Layer(layers.LayerTypePFLog); pflogLayer != nil {
			pflog, _ := pflogLayer.(*layers.PFLog)
			pflogEvent := structs.Map(pflog)

			mergeMap(packetEvent, pflogEvent)
		}
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			ipv4Event := structs.Map(ipv4)

			mergeMap(packetEvent, ipv4Event)
		}
		if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			ipv6Event := structs.Map(ipv6)

			mergeMap(packetEvent, ipv6Event)
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			packetEvent["protocol"] = "TCP"
			tcp, _ := tcpLayer.(*layers.TCP)
			tcpEvent := structs.Map(tcp)

			mergeMap(packetEvent, tcpEvent)
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			packetEvent["protocol"] = "UDP"
			udp, _ := udpLayer.(*layers.UDP)
			udpEvent := structs.Map(udp)

			mergeMap(packetEvent, udpEvent)
		}
		jsonEvent, _ := json.Marshal(packetEvent)
		g.Log(string(jsonEvent))
	}
}
func mergeMap(packetEvent map[string]interface{}, additional map[string]interface{}) {

	for key, value := range additional {
		packetEvent[key] = value
	}
}
