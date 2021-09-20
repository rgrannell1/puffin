package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/prometheus/procfs"
)

// Give a file-path, get the corresponding inode
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

// Given a UID, look up the corresponding username
func LookupUsername(uid uint64) (string, error) {
	userData, err := user.LookupId(fmt.Sprint(uid))

	if err != nil {
		return "", err
	}

	return userData.Username, nil
}

// List pids by reading /proc/<id> folders
func ListPids(pfs *procfs.FS) (map[uint64][]int, map[int]int, error) {
	info, _ := ioutil.ReadDir("/proc/")
	pidsForInode := make(map[uint64][]int)
	pidsToParent := make(map[int]int)

	// list every file in /proc
	for _, file := range info {
		fname := file.Name()

		// assume numeric directories in /proc are pids
		if pid, err := strconv.Atoi(fname); err == nil {
			proc, _ := pfs.Proc(pid)
			info, _ := proc.FileDescriptors()

			// get the parent pid, so we can reconstruct a pid-tree (may not work correctly over-time if IDs are replaced)
			stat, _ := proc.Stat()

			if stat.PPID > 0 {
				pidsToParent[pid] = stat.PPID
			}

			// for every file descriptor in this process...
			for _, fd := range info {
				fpath := "/proc/" + fmt.Sprint(pid) + "/fd/" + fmt.Sprint(fd)

				inode := GetInode(&fpath)

				// register that this inode also uses this pid
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

	return pidsForInode, pidsToParent, nil
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

func PidToCommandline(pfs *procfs.FS, pid int) string {
	pidFs, err := pfs.Proc(pid)

	if err != nil {
		return "?"
	}

	comm, err := pidFs.CmdLine()

	if err != nil {
		return "?"
	}

	return strings.Join(comm, " ")
}

// Given a pid, recursively find its parents
func PidParents(pid int, parents map[int]int) []int {
	pids := []int{}

	currPid := pid
	for {
		ppid, ok := parents[currPid]

		// just to avoid mischief, limit the pid depth to 20
		if len(pids) > 20 || !ok {
			return pids
		} else {
			pids = append(pids, ppid)
			currPid = ppid
		}
	}
}

func AssociateProcesses(pfs *procfs.FS, conns []Connection) *[]PidSocket {
	// get all pids from /proc/
	pidsForInode, pidParents, _ := ListPids(pfs)

	//pidToProcessInfo := make(map[uint64]ProcessInfo)
	pidSockets := make([]PidSocket, 0)
	uidToUsername := make(map[uint64]string)

	// associate each pid to a socket where possible
	for _, conn := range conns {
		conn := conn.(Connection)

		if pids, ok := pidsForInode[conn.Inode()]; ok {
			for _, pid := range pids {
				dt := time.Now()

				// associate uids to user-names, with a fallback value when this fails
				_, ok := uidToUsername[conn.UID()]

				if !ok {
					userName, _ := LookupUsername(conn.UID())
					if len(userName) == 0 {
						uidToUsername[conn.UID()] = "?"
					} else {
						uidToUsername[conn.UID()] = userName
					}
				}

				sock := PidSocket{
					uidToUsername[conn.UID()],
					PidToCommand(pfs, pid),
					PidToCommandline(pfs, pid),
					pid,
					PidParents(pid, pidParents),
					conn,
					dt,
				}

				pidSockets = append(pidSockets, sock)
			}
		}
	}

	return &pidSockets
}

// Main application
func Puffin(json bool, seconds int) int {
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
			err := ReportNetwork(&pidConns, store, false) // TODO

			if err != nil {
				log.Fatal(err)
				return 1
			}

			storeLock.Unlock()
			return 0
		}
	}
}

func main() {
	usage := `
Usage:
  puffin
  puffin capture [(-j|--json)|(-d|--db)] [-s <seconds|--seconds <seconds>]
	puffin analyse <db> [-q <str>|--query <str>] [-f <fpath>|--file <fpath>]
	puffin (-h|--help)

Description:
  Process-aware network-tracing & analysis. Like nethogs, puffin allows you to break down traffic per process. Unlike nethogs, puffin
	can be run in interactive and non-interactive mode, and outputs detailed network information as JSON or an SQLite database for
	detailed analysis.

Modes:
  capture: Capture network traffic and identify processes, connections, protocols, devices, and packets with ongoing networking
	analyse: Analyse a puffin trace using SQL to identify top-talkers, total network-traffic, processes using the network, total-connections, or
	             anything else helpful.

Protocols:
  Puffin currently supports the following protocols:

	* IPv4
	* IPv6
	* UDP
	* TCP

Options:
	-i, --interactive                    start in interactive mode.
  -j, --json                           output aggregated connection-information JSON.
	-d, --db                             output aggregated connection-information to a SQLITE database.
	-s <seconds>, --seconds <seconds>    how mnay seconds should it run for?

See Also:
  nethogs, ss, lsof -i

License:
  The MIT License

  Copyright (c) 2021 Róisín Grannell

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
	`

	opts, _ := docopt.ParseDoc(usage)
	json, _ := opts.Bool("--json")

	seconds, _ := opts.Int("--seconds")

	Puffin(json, seconds)
}
