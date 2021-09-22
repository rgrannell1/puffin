package main

import (
	"fmt"
	"net"
	"time"
)

type Connection interface {
	GetLocalAddr() net.IP
	GetLocalPort() uint64
	GetRemAddr() net.IP
	GetRemPort() uint64
	GetUID() uint64
	GetInode() uint64
	GetId() string
	GetType() string
}

// Represents an association between process-based information (user, command, pid), and a
// transport-layer connection
type PidSocket struct {
	UserName    string     `json:"username"`
	Command     string     `json:"command"`
	CommandLine string     `json:"command_line"`
	Pid         int        `json:"pid"`
	PidParents  []int      `json:"parent_pids"`
	Connection  Connection `json:"connection"`
	Time        time.Time  `json:"time"`
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
func (pkt *PacketData) GetId() string {
	return pkt.LocalAddr.String() + fmt.Sprint(pkt.LocalPort) + pkt.RemAddr.String() + fmt.Sprint(pkt.RemPort)
}

func (conn *PidSocket) GetId() string {
	return conn.Connection.GetId()
}

// TODO add connid here
type StoredConnectionData struct {
	LocalAddr net.IP
	LocalPort uint64
	RemAddr   net.IP
	RemPort   uint64
	Size      int                // Information we accumulate over time for each connection
	From      int                // The time the least recent was received,
	To        int                // The time the most recent packet was received
	Packets   []StoredPacketData // Information about each packet received
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
