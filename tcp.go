package main

import (
	"crypto/sha256"
	"io"
	"log"
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

// Watch /proc/net/tcp and /proc/net/tcp6 for changes
func NetTCPWatcher(tcpChan chan []TCPConnection, pfs *procfs.FS) {
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
				mconns[idx] = TCPConnection{0, conn.Sl, conn.LocalAddr, conn.LocalPort, conn.RemAddr, conn.RemPort, conn.St, conn.TxQueue, conn.RxQueue, conn.UID, conn.Inode}
			}
		}

		currHashv6, _ := ProcHash(false)

		if hashv6 != currHashv6 {
			changed = true
			hashv6 = currHashv6

			// todo expand array
			conns, _ := pfs.NetTCP6()

			for _, conn := range conns {
				mconns = append(mconns, TCPConnection{0, conn.Sl, conn.LocalAddr, conn.LocalPort, conn.RemAddr, conn.RemPort, conn.St, conn.TxQueue, conn.RxQueue, conn.UID, conn.Inode})
			}
		}

		if changed {
			tcpChan <- mconns
		}

		time.Sleep(500 * time.Millisecond)
	}
}
