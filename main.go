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

func AssociateProcesses(pfs *procfs.FS, conns []TCPConnection) []PidSocket {
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

	return pidSockets
}

func ListNetworkDevices(pfs *procfs.FS) ([]string, error) {
	devs, error := pfs.NetDev()

	if error != nil {
		return nil, error
	}

	idx := 0
	deviceNames := make([]string, len(devs))
	for name := range devs {
		deviceNames[idx] = name
		idx++
	}

	return deviceNames, nil
}

func PacketWatcher(packetChan chan PacketData, pfs *procfs.FS) {
	deviceNames, _ := ListNetworkDevices(pfs)

	for _, device := range deviceNames {
		go EmitDevicePackets(device)
	}
}

func AssociatePackets(pfs *procfs.FS, pidConns *[]PidSocket) {

}

func NetworkProcessWatcher(pfs *procfs.FS) {
	tcpChan := make(chan []TCPConnection)
	packetChan := make(chan PacketData)

	go NetTCPWatcher(tcpChan, pfs)
	go PacketWatcher(packetChan, pfs)

	for {
		conns := <-tcpChan
		pidConns := AssociateProcesses(pfs, conns)
		AssociatePackets(pfs, &pidConns)
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
