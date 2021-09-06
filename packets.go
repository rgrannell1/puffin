package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func EmitDevicePackets(packetChan chan PacketData, device string) {
	handle, err := pcap.OpenLive(device, 262144, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for pkt := range packets {

		packetChan <- PacketData{device}
	}
}
