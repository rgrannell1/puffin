package main

import (
	"fmt"
	"net"
	"os/user"
	"strings"
	"time"
)

func (conn *TCPConnection) String() string {
	message := []string{
		"",
		conn.LocalAddr.String(),
		":",
		fmt.Sprint(conn.LocalPort),
		" -> ",
		conn.RemAddr.String(),
		":",
		fmt.Sprint(conn.RemPort),
	}

	return strings.Join(message, "")
}

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

func (pidSocket *PidSocket) String() string {
	owner, _ := user.LookupId(fmt.Sprint(pidSocket.Connection.UID))

	return owner.Username + " " + fmt.Sprint(pidSocket.Pid) + " " + pidSocket.Command + " " + pidSocket.Connection.String()
}

type PidSocket struct {
	UserName   string
	Command    string
	Pid        int
	Connection TCPConnection
	Time       time.Time
}

type PacketData struct {
	Device    string
	Timestamp int64
	LocalAddr net.IP
	LocalPort uint64
	RemAddr   net.IP
	RemPort   uint64
	Size      int
}

type PacketStore = map[string]map[string][]StoredPacketData

func ShowPacketStore(store PacketStore) {
	for device, byConn := range store {
		fmt.Println(device + ": (device)")
		for id, stored := range byConn {
			fmt.Println("   " + id + ":(id)")
			for _, elem := range stored {
				fmt.Println(elem)
			}
		}
	}
}

type StoredPacketData struct {
	Timestampt int64
	Size       int
}

type Identifiable interface {
	Id() string
}

func (pkt *PacketData) Id() string {
	return string(pkt.LocalAddr) + fmt.Sprint(pkt.LocalPort) + string(pkt.RemAddr) + fmt.Sprint(pkt.RemPort)
}
