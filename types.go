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
func SocketId(conn *TCPConnection) string {
	return conn.LocalAddr.String() + string(conn.LocalPort) + conn.RemAddr.String() + string(conn.RemPort) + "tcp"
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
	LocalAddr net.IP
	LocalPort uint64
	RemAddr   net.IP
	RemPort   uint64
	Size      int
}

type ProcessInfo struct {
}
