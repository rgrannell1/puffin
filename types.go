package main

import (
	"fmt"
	"net"
	"time"
)

// Represents a TCP Connection, based on Procfs's export
type TCPConnection struct {
	SL        uint64
	LocalAddr net.IP
	LocalPort uint64
	RemAddr   net.IP
	RemPort   uint64
	St        uint64
	TxQueue   uint64
	RxQueue   uint64
	UID       uint64
	Inode     uint64
}

// base the socket-id on the 4-tuple (localip, localport, remip, remport)
// lets assume IPs will always have the same representation for now
func (conn *TCPConnection) Id() string {
	return conn.LocalAddr.String() + fmt.Sprint(conn.LocalPort) + conn.RemAddr.String() + fmt.Sprint(conn.RemPort)
}

// Represents an association between process-based information (user, command, pid), and a
// transport-layer connection
type PidSocket struct {
	UserName   string
	Command    string
	Pid        int
	Connection TCPConnection
	Time       time.Time
}

// Information to extract from each packet, where possible.
// If port information is unavailable, return IP-layer information only.
type PacketData struct {
	Device    string
	Timestamp int64
	LocalAddr net.IP
	LocalPort uint64
	RemAddr   net.IP
	RemPort   uint64
	Size      int
}

// Store packets by <device>.<connid> as an array of some packet-data
type PacketStore = map[string]map[string][]StoredPacketData

// Only store packet timestamps and size, the reset of the information can be
// recovered from storage context
type StoredPacketData struct {
	Timestampt int64
	Size       int
}

// Given extracted packet-information, return a connection ID
func (pkt *PacketData) Id() string {
	return string(pkt.LocalAddr) + fmt.Sprint(pkt.LocalPort) + string(pkt.RemAddr) + fmt.Sprint(pkt.RemPort)
}
