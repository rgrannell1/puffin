package main

import (
	"fmt"
	"net"
	"time"

	"github.com/prometheus/procfs"
)

// Watch /proc/net/udp and /proc/net/udp6 for changes by emitting a file-change
// periodically
func NetUDPWatcher(udpChan chan []Connection, pfs *procfs.FS) {
	hashv4 := ""
	hashv6 := ""

	for {
		changed := false
		currHashv4, _ := ProcHash(false)

		mconns := make([]Connection, 0)

		if hashv4 != currHashv4 {
			changed = true
			hashv4 = currHashv4

			conns, _ := pfs.NetUDP()
			mconns = make([]Connection, len(conns))

			for idx, conn := range conns {
				mconns[idx] = UDPConnection{conn.Sl, conn.LocalAddr, conn.RemAddr, conn.St, conn.TxQueue, conn.RxQueue, conn.UID, conn.Inode}
			}
		}

		currHashv6, _ := ProcHash(false)

		if hashv6 != currHashv6 {
			changed = true
			hashv6 = currHashv6

			// todo expand array
			conns, _ := pfs.NetUDP6()

			for _, conn := range conns {
				udpConn := UDPConnection{conn.Sl, conn.LocalAddr, conn.RemAddr, conn.St, conn.TxQueue, conn.RxQueue, conn.UID, conn.Inode}
				mconns = append(mconns, udpConn)
			}
		}

		if changed {
			udpChan <- mconns
		}

		time.Sleep(500 * time.Millisecond)
	}
}

type UDPConnection struct {
	sl        uint64 `json:"sl"`
	localAddr net.IP `json:"localaddr"`
	remAddr   net.IP `json:"remaddr"`
	st        uint64 `json:"st"`
	txQueue   uint64 `json:"txqueue"`
	rxQueue   uint64 `json:"rxqueue"`
	uid       uint64 `json:"uid"`
	inode     uint64 `json:"inode"`
}

func (conn UDPConnection) Id() string {
	return conn.LocalAddr().String() + fmt.Sprint(conn.LocalPort()) + conn.RemAddr().String() + fmt.Sprint(conn.RemPort())
}

func (udp UDPConnection) SL() uint64 {
	return udp.sl
}

func (udp UDPConnection) ST() uint64 {
	return udp.st
}

func (udp UDPConnection) TxQueue() uint64 {
	return udp.txQueue
}

func (udp UDPConnection) RxQueue() uint64 {
	return udp.rxQueue
}

func (udp UDPConnection) GetType() string {
	return "UDP"
}

func (udp UDPConnection) LocalAddr() net.IP {
	return udp.localAddr
}

func (udp UDPConnection) LocalPort() uint64 {
	return 0
}

func (udp UDPConnection) RemAddr() net.IP {
	return udp.remAddr
}

func (udp UDPConnection) RemPort() uint64 {
	return 0
}

func (udp UDPConnection) UID() uint64 {
	return udp.uid
}

func (udp UDPConnection) Inode() uint64 {
	return udp.inode
}
