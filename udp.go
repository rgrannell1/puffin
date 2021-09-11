package main

import (
	"time"

	"github.com/prometheus/procfs"
)

// Watch /proc/net/udp and /proc/net/udp6 for changes by emitting a file-change
// periodically
func NetUDPWatcher(udpChan chan []TCPConnection, pfs *procfs.FS) {
	hashv4 := ""
	hashv6 := ""

	for {
		changed := false
		currHashv4, _ := ProcHash(false)

		mconns := make([]TCPConnection, 0)

		if hashv4 != currHashv4 {
			changed = true
			hashv4 = currHashv4

			conns, _ := pfs.NetTCP()
			mconns = make([]TCPConnection, len(conns))

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
			udpChan <- mconns
		}

		time.Sleep(500 * time.Millisecond)
	}
}
