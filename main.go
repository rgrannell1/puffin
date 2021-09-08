package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/prometheus/procfs"
)

func GetInode(fpath *string) uint64 {
	// it's really odd I need a direct syscall to get an inode...
	// this will fail horribly on windows

	var stat syscall.Stat_t
	if err := syscall.Stat(*fpath, &stat); err != nil {
		return 0
	}

	return stat.Ino
}

const CLEAR_STRING = "\x1b\x5b\x48\x1b\x5b\x32\x4a"

func LookupUsername(id uint64) (string, error) {
	userData, err := user.LookupId(fmt.Sprint(id))

	if err != nil {
		return "", err
	}

	return userData.Username, nil
}

// List pids by reading /proc/<id> folders
func ListPids(pfs *procfs.FS) (map[uint64][]int, error) {
	info, _ := ioutil.ReadDir("/proc/")
	pidsForInode := make(map[uint64][]int)

	for _, file := range info {
		fname := file.Name()

		// assume numeric directories in /proc are pids
		if pid, err := strconv.Atoi(fname); err == nil {
			proc, _ := pfs.Proc(pid)
			info, _ := proc.FileDescriptors()

			for _, fd := range info {
				fpath := "/proc/" + fmt.Sprint(pid) + "/fd/" + fmt.Sprint(fd)

				inode := GetInode(&fpath)

				if inode > 0 {
					if pids, ok := pidsForInode[inode]; ok {
						pidsForInode[inode] = append(pids, pid)
					} else {
						pidsForInode[inode] = []int{pid}
					}
				}
			}
		}
	}

	return pidsForInode, nil
}

func PidToCommand(pfs *procfs.FS, pid int) string {
	pidFs, err := pfs.Proc(pid)

	if err != nil {
		return "?"
	}

	comm, err := pidFs.Comm()

	if err != nil {
		return "?"
	}

	return comm
}

func AssociateProcesses(pfs *procfs.FS, conns []TCPConnection) *[]PidSocket {
	// get all pids from /proc/
	pidsForInode, _ := ListPids(pfs)

	//pidToProcessInfo := make(map[uint64]ProcessInfo)
	pidSockets := make([]PidSocket, 0)
	uidToUsername := make(map[uint64]string)

	// associate each pid to a socket where possible
	for _, conn := range conns {
		if pids, ok := pidsForInode[conn.Inode]; ok {
			for _, pid := range pids {
				dt := time.Now()

				// associate uids to user-names, with a fallback value when this fails
				_, ok := uidToUsername[conn.UID]

				if !ok {
					userName, _ := LookupUsername(conn.UID)
					if len(userName) == 0 {
						uidToUsername[conn.UID] = "?"
					} else {
						uidToUsername[conn.UID] = userName
					}
				}

				pidSockets = append(pidSockets, PidSocket{uidToUsername[conn.UID], PidToCommand(pfs, pid), pid, conn, dt})
			}
		}
	}

	return &pidSockets
}

// Main application
func Porcus(json bool, seconds int) int {
	start := time.Now()

	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		log.Fatal(err)
		return 1
	}

	pidConnChan := make(chan *[]PidSocket)
	packetChan := make(chan *PacketData)

	pidConns := []PidSocket{}
	packets := []PacketData{}

	go NetworkWatcher(&pfs, packetChan, pidConnChan)

	var storeLock sync.Mutex

	store := map[string]map[string]StoredConnectionData{}

	for {
		select {
		case tmp := <-pidConnChan:
			// full is returned each time, append

			storeLock.Lock()
			pidConns = []PidSocket{}
			pidConns = append(pidConns, *tmp...)
			storeLock.Unlock()

		case pkt := <-packetChan:
			packets = append(packets, *pkt)

			storeLock.Lock()
			AssociatePacket(store, &pidConns, *pkt)
			storeLock.Unlock()
		}

		if json && time.Since(start) > time.Second*time.Duration(seconds) {
			storeLock.Lock()
			ReportNetwork(&pidConns, store)
			storeLock.Unlock()
			return 0
		}
	}
}

func main() {
	usage := `
Usage:
  porcus [-j|--json] [-s <seconds|--seconds <seconds>]
	porcus [-h|--help]

Description:
  Monitor machine network-traffic.

Options:
  -j, --json                           output as JSON.
	-s <seconds>, --seconds <seconds>    how mnay seconds should it run for?
	`

	opts, _ := docopt.ParseDoc(usage)
	json, _ := opts.Bool("--json")

	seconds, _ := opts.Int("--seconds")

	Porcus(json, seconds)
}
