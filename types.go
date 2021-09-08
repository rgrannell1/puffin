package main

import (
	"fmt"
	"net"
	"time"
)

// Represents a TCP Connection, based on Procfs's export
type TCPConnection struct {
	SL        uint64 `json:"sl"`
	LocalAddr net.IP `json:"localaddr"`
	LocalPort uint64 `json:"localport"`
	RemAddr   net.IP `json:"remaddr"`
	RemPort   uint64 `json:"remport"`
	St        uint64 `json:"st"`
	TxQueue   uint64 `json:"txqueue"`
	RxQueue   uint64 `json:"rxqueue"`
	UID       uint64 `json:"uid"`
	Inode     uint64 `json:"inode"`
}

// base the socket-id on the 4-tuple (localip, localport, remip, remport)
// lets assume IPs will always have the same representation for now
func (conn *TCPConnection) Id() string {
	return conn.LocalAddr.String() + fmt.Sprint(conn.LocalPort) + conn.RemAddr.String() + fmt.Sprint(conn.RemPort)
}

// Represents an association between process-based information (user, command, pid), and a
// transport-layer connection
type PidSocket struct {
	UserName   string        `json:"username"`
	Command    string        `json:"command"`
	Pid        int           `json:"pid"`
	Connection TCPConnection `json:"connection"`
	Time       time.Time     `json:"time"`
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
	Timestamp int64 `json:"timestamp"`
	Size      int   `json:"size"`
}

// Given extracted packet-information, return a connection ID
func (pkt *PacketData) Id() string {
	return pkt.LocalAddr.String() + fmt.Sprint(pkt.LocalPort) + pkt.RemAddr.String() + fmt.Sprint(pkt.RemPort)
}

func (conn *PidSocket) Id() string {
	return conn.Connection.Id()
}

type StoredConnectionData struct {
	Size    int
	From    int
	To      int
	Packets []StoredPacketData
}

type MachineNetworkStorage = map[string]map[string]StoredConnectionData

type OutputRow struct {
	Device        string             `json:"device"`
	ProcessSocket PidSocket          `json:"process_socket"`
	TotalBytes    int                `json:"bytes"`
	From          int                `json:"from"`
	To            int                `json:"to"`
	Packets       []StoredPacketData `json:"packets"`
}
