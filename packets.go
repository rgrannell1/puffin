package main

import (
	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/procfs"
)

// Extract connection-information and size from each packet
func ExtractPacketData(device string, pkt gopacket.Packet) PacketData {
	pckData := PacketData{}
	pckData.Device = device
	pckData.Timestamp = pkt.Metadata().Timestamp.UnixNano()

	// decode IPv4 or IPv6 layer
	if layer := pkt.Layer(layers.LayerTypeIPv4); layer != nil {
		ipv4 := layer.(*layers.IPv4)
		pckData.LocalAddr = ipv4.SrcIP
		pckData.RemAddr = ipv4.DstIP
	} else if layer := pkt.Layer(layers.LayerTypeIPv6); layer != nil {
		ipv6 := layer.(*layers.IPv6)
		pckData.LocalAddr = ipv6.SrcIP
		pckData.RemAddr = ipv6.DstIP
	}

	// Decode TPC layer if present
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		pckData.LocalPort = uint64(tcp.SrcPort)
		pckData.RemPort = uint64(tcp.DstPort)
	}

	// TODO UDP or other layer
	pckData.Size = len(pkt.Data())

	return pckData
}

// Emit packet-information for each device to a shared channel.
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

// Store packet information into a <device>.<conn-id> to packet-data array map
func StorePacket(store PacketStore, pkt *PacketData) PacketStore {
	id := pkt.Id()

	stored := StoredPacketData{
		pkt.Timestamp,
		pkt.Size,
	}

	// TODO for the moment, append and store. This is _horribly_ inefficient
	if _, ok := store[pkt.Device]; ok {
		store[pkt.Device][id] = append(store[pkt.Device][id], stored)
	} else {
		store[pkt.Device] = map[string][]StoredPacketData{}
		store[pkt.Device][id] = append(store[pkt.Device][id], stored)
	}

	return store
}

// Watch for packets on each present device
func PacketWatcher(packetChan chan PacketData, pfs *procfs.FS) {
	deviceNames, _ := ListNetworkDevices(pfs)

	for _, device := range deviceNames {
		go EmitDevicePackets(packetChan, device)
	}
}

func AssociatePackets(pfs *procfs.FS, machineNetStore MachineNetworkStorage, packetStore PacketStore, pidConns *[]PidSocket) {
	for device, connPackets := range packetStore {
		for connId, packets := range connPackets {
			if _, ok := machineNetStore[device]; !ok {
				machineNetStore[device] = map[string]StoredConnectionData{}
			}

			size := 0
			first := int(math.Inf(0))
			last := 0

			for _, pkt := range packets {
				size += pkt.Size

				if int(pkt.Timestamp) < first {
					first = int(pkt.Timestamp)
				}

				if int(pkt.Timestamp) > last {
					last = int(pkt.Timestamp)
				}
			}

			machineNetStore[device][connId] = StoredConnectionData{
				Size:    size,
				From:    first,
				To:      last,
				Packets: packets,
			}
		}
	}

}
