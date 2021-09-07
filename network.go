package main

import "github.com/prometheus/procfs"

func ListNetworkDevices(pfs *procfs.FS) ([]string, error) {
	devs, error := pfs.NetDev()

	if error != nil {
		return nil, error
	}

	idx := 0
	deviceNames := make([]string, len(devs))
	for name := range devs {
		deviceNames[idx] = name
		idx++
	}

	return deviceNames, nil
}

// Watch network traffic and /proc information about network-devices
// and connections.
func NetworkWatcher(pfs *procfs.FS, storeChan chan PacketStore, pidConnChan chan *[]PidSocket) {
	tcpChan := make(chan []TCPConnection)
	packetChan := make(chan PacketData)

	go NetTCPWatcher(tcpChan, pfs)
	go PacketWatcher(packetChan, pfs)

	pktStore := PacketStore{}

	for {
		select {
		case conns := <-tcpChan:
			// join process information to connection information
			pidConnChan <- AssociateProcesses(pfs, conns)
		case pkt := <-packetChan:
			// store the pick

			storeChan <- StorePacket(pktStore, &pkt)
		}
	}
}
