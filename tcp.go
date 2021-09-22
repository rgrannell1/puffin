package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/prometheus/procfs"
)

func ProcHash(v6 bool) (string, error) {
	// -- I don't know a better method than read twice, once for content, once for a hash
	var fpath string
	if v6 {
		fpath = "/proc/net/tcp6"
	} else {
		fpath = "/proc/net/tcp"
	}

	procNetTcp, err := os.Open(fpath)
	if err != nil {
		return "", err
	}

	defer func() {
		procNetTcp.Close()
	}()
	currHash := sha256.New()
	if _, err := io.Copy(currHash, procNetTcp); err != nil {
		log.Fatal(err)
	}

	return string(currHash.Sum(nil)), err
}

// Watch /proc/net/tcp and /proc/net/tcp6 for changes by emitting a file-change
// periodically
func NetTCPWatcher(tcpChan chan []Connection, pfs *procfs.FS) {
	hashv4 := ""
	hashv6 := ""

	for {
		changed := false
		currHashv4, _ := ProcHash(false)

		mconns := make([]Connection, 0)

		if hashv4 != currHashv4 {
			changed = true
			hashv4 = currHashv4

			conns, _ := pfs.NetTCP()
			mconns = make([]Connection, len(conns))

			for idx, conn := range conns {
				tcpConn := TCPConnection{conn.Sl, conn.LocalAddr, conn.LocalPort, conn.RemAddr, conn.RemPort, conn.St, conn.TxQueue, conn.RxQueue, conn.UID, conn.Inode}
				mconns[idx] = tcpConn
			}
		}

		currHashv6, _ := ProcHash(false)

		if hashv6 != currHashv6 {
			changed = true
			hashv6 = currHashv6

			// todo expand array
			conns, _ := pfs.NetTCP6()

			for _, conn := range conns {
				tcpConn := TCPConnection{conn.Sl, conn.LocalAddr, conn.LocalPort, conn.RemAddr, conn.RemPort, conn.St, conn.TxQueue, conn.RxQueue, conn.UID, conn.Inode}
				mconns = append(mconns, tcpConn)
			}
		}

		if changed {
			tcpChan <- mconns
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// Represents a TCP Connection, based on Procfs's export
type TCPConnection struct {
	sl        uint64 `json:"sl"`
	localAddr net.IP `json:"localaddr"`
	localPort uint64 `json:"localport"`
	remAddr   net.IP `json:"remaddr"`
	remPort   uint64 `json:"remport"`
	st        uint64 `json:"st"`
	txQueue   uint64 `json:"txqueue"`
	rxQueue   uint64 `json:"rxqueue"`
	uid       uint64 `json:"uid"`
	inode     uint64 `json:"inode"`
}

func (tcp TCPConnection) GetSL() uint64 {
	return tcp.sl
}

func (tcp TCPConnection) GetST() uint64 {
	return tcp.st
}

func (tcp TCPConnection) GetTxQueue() uint64 {
	return tcp.txQueue
}

func (tcp TCPConnection) GetRxQueue() uint64 {
	return tcp.rxQueue
}

func (tcp TCPConnection) GetType() string {
	return "TCP"
}

func (tcp TCPConnection) GetLocalAddr() net.IP {
	return tcp.localAddr
}

func (tcp TCPConnection) GetLocalPort() uint64 {
	return tcp.localPort
}

func (tcp TCPConnection) GetRemAddr() net.IP {
	return tcp.remAddr
}

func (tcp TCPConnection) GetRemPort() uint64 {
	return tcp.remPort
}

func (tcp TCPConnection) GetUID() uint64 {
	return tcp.uid
}

func (tcp TCPConnection) GetInode() uint64 {
	return tcp.inode
}

// base the socket-id on the 4-tuple (localip, localport, remip, remport)
// lets assume IPs will always have the same representation for now
func (conn TCPConnection) GetId() string {
	return conn.GetLocalAddr().String() + fmt.Sprint(conn.GetLocalPort()) + conn.GetRemAddr().String() + fmt.Sprint(conn.GetRemPort())
}
