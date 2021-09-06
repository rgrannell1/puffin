package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/prometheus/procfs"
)

type SysStat struct {
	Ino int
}

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
	userData, err := user.LookupId(string(id))

	if err != nil {
		return "", err
	}

	return userData.Username, nil
}

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
						pidsForInode[inode] = []int{pid} // lookup pids too!
					}
				}
			}
		}
	}

	return pidsForInode, nil
}

func AssociateProcesses(pfs *procfs.FS, conns []TCPConnection) []PidSocket {
	// list process fd

	pidsForInode, _ := ListPids(pfs)

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

				pidSockets = append(pidSockets, PidSocket{uidToUsername[conn.UID], pid, conn, dt})
			}
		}
	}

	return pidSockets
}

func NetworkProcessWatcher(pfs *procfs.FS) {
	tcpChan := make(chan []TCPConnection)

	go NetTCPWatcher(tcpChan, pfs)

	for {
		conns := <-tcpChan
		pidConns := AssociateProcesses(pfs, conns)

		for _, conn := range pidConns {
			fmt.Println(conn.String())
		}
	}
}

// Main application
func Porcus() int {
	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		log.Fatal(err)
		return 1
	}

	go NetworkProcessWatcher(&pfs)
	for {
	}

	return 0
}

func main() {
	usage := `
Usage:
  porcus
	porcus [-h|--help]
	`
	docopt.ParseDoc(usage)
	Porcus()
}
