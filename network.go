package main

import "github.com/prometheus/procfs"

// List network devices from /proc/net/dev
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
func NetworkWatcher(pfs *procfs.FS, packetChan chan *PacketData, pidConnChan chan *[]PidSocket) {
	tcpChan := make(chan []TCPConnection)

	go NetTCPWatcher(tcpChan, pfs)
	go PacketWatcher(packetChan, pfs)

	for {
		pidConnChan <- AssociateProcesses(pfs, <-tcpChan)
	}
}
