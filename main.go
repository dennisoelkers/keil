package main

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/robertkowalski/graylog-golang"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"os"
	"strings"
	"time"
)

var (
	fromFile = kingpin.Flag("file", "Read from file instead of device").Short('f').Bool()
	promisc = kingpin.Flag("promisc", "Defines if interface is flagged promiscous").Short('P').Default("true").Bool()
	source = kingpin.Arg("source", "Name of device/filename to read from").Required().String()
	host = kingpin.Flag("host", "Hostname of Graylog server").Default("localhost").Short('h').String()
	port = kingpin.Flag("port", "Port of Graylog Server").Default("12201").Short('p').Int()
	facility = kingpin.Flag("facility", "The facility identifier used for logging").Default("pflog").String()
)

func getSource(fromFile bool, sourceName string, promisc bool) (*pcap.Handle, error) {
	if (fromFile) {
		return pcap.OpenOffline(sourceName)
	} else {
		return pcap.OpenLive(sourceName, 1500, promisc, time.Millisecond)
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

	handle, err := getSource(*fromFile, sourceName, *promisc)

	if (err != nil) {
		logger.Panic("Error: ", sourceName, err)
	} else {
		logger.Println("Capturing from", sourceName, ", link type: ", handle.LinkType())
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		packetEvent := make(map[string]interface{})
		packetEvent["version"] = "1.0"
		hostname, err := os.Hostname()
		if (err != nil) {
			hostname = "unknown"
		}
		packetEvent["host"] = hostname
		packetEvent["timestamp"] = time.Now().UTC().String()
		packetEvent["facility"] = *facility
		packetEvent["short_message"] = packet.String()

		layers := make([]string, len(packet.Layers()))

		for idx, layer := range packet.Layers() {
			layers[idx] = layer.LayerType().String()
			handlePacketLayer(packetEvent, layer)
		}

		packetEvent["layers"] = strings.Join(layers, "->")

		jsonEvent, _ := json.Marshal(packetEvent)
		g.Log(string(jsonEvent))
	}
}
