package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ExtractPacketData(device string, pkt gopacket.Packet) PacketData {
	pckData := PacketData{}
	pckData.Device = device

	if layer := pkt.Layer(layers.LayerTypeIPv4); layer != nil {
		ipv4 := layer.(*layers.IPv4)
		pckData.LocalAddr = ipv4.SrcIP
		pckData.RemAddr = ipv4.DstIP
	} else if layer := pkt.Layer(layers.LayerTypeIPv6); layer != nil {
		ipv6 := layer.(*layers.IPv6)
		pckData.LocalAddr = ipv6.SrcIP
		pckData.RemAddr = ipv6.DstIP
	}

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		pckData.LocalPort = uint64(tcp.SrcPort)
		pckData.RemPort = uint64(tcp.DstPort)
	}

	pckData.Size = len(pkt.Data())

	return pckData
}

func EmitDevicePackets(packetChan chan PacketData, device string) {
	handle, err := pcap.OpenLive(device, 262144, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for pkt := range packets {
		packetChan <- ExtractPacketData(device, pkt)
	}
}
