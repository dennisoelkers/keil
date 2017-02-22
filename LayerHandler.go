package main

import (
	"bytes"
	"encoding/gob"
	"github.com/fatih/structs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strings"
)

type LayerHandlerFunc func(map[string]interface{}, gopacket.Layer)

var LayerHandlerMap = make(map[gopacket.LayerType]LayerHandlerFunc)

func GetBytes(key interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(key)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func handlePfLog(event map[string]interface{}, layer gopacket.Layer) {
	pflog, _ := layer.(*layers.PFLog)
	pflogEvent := structs.Map(pflog)

	for key, value := range pflogEvent {
		if (key == "IFName" || key == "Ruleset") {
			byteArr, err := GetBytes(pflogEvent[key])
			if (err == nil) {
				event[key] = string(byteArr[:])
			}
			continue
		}
		event[key] = value
	}
}

func handleIPv4(event map[string]interface{}, layer gopacket.Layer) {
	ipv4, _ := layer.(*layers.IPv4)
	ipv4Event := structs.Map(ipv4)

	for key, value := range ipv4Event {
		if (key == "Protocol") {
			protocolNumber, ok := value.(layers.IPProtocol)
			if (ok) {
				protocolName := layers.IPProtocolMetadata[protocolNumber].Name
				event[key] = protocolName
			} else {
				event[key] = value
			}
		}
		event[key] = value
	}
}

func handleIPv6(event map[string]interface{}, layer gopacket.Layer) {
	ipv6, _ := layer.(*layers.IPv6)
	ipv6Event := structs.Map(ipv6)

	mergeMap(event, ipv6Event)
}

func handleTCP(event map[string]interface{}, layer gopacket.Layer) {
	event["protocol"] = "TCP"
	tcp, _ := layer.(*layers.TCP)
	tcpEvent := structs.Map(tcp)

	for key, value := range tcpEvent {
		if (key == "Options") {
			options, ok := value.([]layers.TCPOption)
			if (ok) {
				optionsList := make([]string, len(options))
				for idx, option := range options {
					optionsList[idx] = option.String()
				}
				event[key] = strings.Join(optionsList, ",")
			} else {
				event[key] = value
			}
		}
		event[key] = value
	}
}

func handleUDP(event map[string]interface{}, layer gopacket.Layer) {
	event["protocol"] = "UDP"
	udp, _ := layer.(*layers.UDP)
	udpEvent := structs.Map(udp)

	mergeMap(event, udpEvent)
}

func init() {
	LayerHandlerMap[layers.LayerTypePFLog] = handlePfLog
	LayerHandlerMap[layers.LayerTypeIPv4] = handleIPv4
	LayerHandlerMap[layers.LayerTypeIPv6] = handleIPv6
	LayerHandlerMap[layers.LayerTypeTCP] = handleTCP
	LayerHandlerMap[layers.LayerTypeUDP] = handleUDP
}

func handlePacketLayer(event map[string]interface{}, layer gopacket.Layer) error {
	handlerFunc := LayerHandlerMap[layer.LayerType()]

	if (handlerFunc != nil) {
		handlerFunc(event, layer)
	} else {
		hangleGenericLayer(event, layer)
	}
	return nil
}
func hangleGenericLayer(event map[string]interface{}, layer gopacket.Layer) {
}

func mergeMap(packetEvent map[string]interface{}, additional map[string]interface{}) {
	for key, value := range additional {
		packetEvent[key] = value
	}
}
