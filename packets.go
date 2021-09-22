package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/procfs"
)

// Extract connection-information and size from each packet
func ExtractPacketData(device string, pkt gopacket.Packet) *PacketData {
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

	return &pckData
}

// Emit packet-information for each device to a shared channel.
func EmitDevicePackets(packetChan chan *PacketData, device string) {
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

// Watch for packets on each present device
func PacketWatcher(packetChan chan *PacketData, pfs *procfs.FS) {
	deviceNames, _ := ListNetworkDevices(pfs)

	for _, device := range deviceNames {
		go EmitDevicePackets(packetChan, device)
	}
}

func AssociatePacket(store MachineNetworkStorage, pidConns *[]PidSocket, pkt PacketData) {
	// if the device is not set, set it!
	if _, ok := store[pkt.Device]; !ok {
		store[pkt.Device] = map[string]StoredConnectionData{}
	}

	id := pkt.GetId()
	if tgt, hasConn := store[pkt.Device][id]; !hasConn {
		// set the initial stored-data for this connection, with a single stored packet
		packets := []StoredPacketData{}
		packets = append(packets, StoredPacketData{
			Timestamp: int64(pkt.Timestamp),
			Size:      int(pkt.Size),
		})

		store[pkt.Device][id] = StoredConnectionData{
			LocalAddr: pkt.LocalAddr,
			LocalPort: pkt.LocalPort,
			RemAddr:   pkt.RemAddr,
			RemPort:   pkt.RemPort,
			Size:      pkt.Size,
			From:      int(pkt.Timestamp),
			To:        int(pkt.Timestamp),
			Packets:   packets,
		}
	} else {
		// update the connection
		tgt.Size += pkt.Size

		if tgt.From > int(pkt.Timestamp) {
			tgt.From = int(pkt.Timestamp)
		}

		if tgt.To < int(pkt.Timestamp) {
			tgt.To = int(pkt.Timestamp)
		}

		tgt.Packets = append(tgt.Packets, StoredPacketData{
			pkt.Timestamp,
			pkt.Size,
		})

		// for some reason I need to create a new struct?
		store[pkt.Device][id] = StoredConnectionData{
			tgt.LocalAddr,
			tgt.LocalPort,
			tgt.RemAddr,
			tgt.RemPort,
			tgt.Size,
			tgt.From,
			tgt.To,
			tgt.Packets,
		}
	}
}
