package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func ReportJSONNetwork(pidConns *[]PidSocket, store MachineNetworkStorage) error {
	for device, deviceConns := range store {
		for connId, connData := range deviceConns {
			for _, pidData := range *pidConns {
				if pidData.Id() == connId {
					// add connection
					data := OutputRow{
						Device:        device,
						ProcessSocket: pidData,
						Packets:       connData.Packets,
						TotalBytes:    connData.Size,
						From:          connData.From,
						To:            connData.To,
					}

					bytes, err := json.MarshalIndent(data, "", "  ")
					if err != nil {
						return err
					}

					fmt.Println(string(bytes))
				}
			}
		}
	}

	return nil
}

const CREATE_TCP_CONN_TABLE = `create table if not exists tcp_conn (
	sl        integer,
	localAddr text,
	localPort integer,
	remAddr   text,
	remPort   integer,
	st        integer,
	txQueue   integer,
	rxQueue   integer,
	uid       integer,
	inode     integer
)`

const CREATE_PROCCESS_CONN_TABLE = `create table if not exists process_conn (
  username       text,
	command        text,
	commandLine    text,
	pid            int,
	inode          int,
	time           int
)`

const CREATE_PID_PARENTS_TABLE = `create table if not exists parent_pid (
  pid    int,
	ppid   int,
	level  int
)`

func ReportDBNetwork(pidConns *[]PidSocket, store MachineNetworkStorage) error {
	os.Create("./puffin.db")
	db, err := sql.Open("sqlite3", "./puffin.db")

	if err != nil {
		return err
	}

	defer func() {
		db.Close()
	}()

	tables := []string{
		CREATE_TCP_CONN_TABLE,
		CREATE_PROCCESS_CONN_TABLE,
		CREATE_PID_PARENTS_TABLE,
	}

	for _, table := range tables {
		_, err = db.Exec(table)
		if err != nil {
			return err
		}
	}

	insert_parent_pid, err := db.Prepare("INSERT INTO parent_pid (pid, ppid, level) values (?, ?, ?)")

	if err != nil {
		return err
	}

	insert_process_conn, err := db.Prepare("INSERT INTO process_conn (username, command, commandLine, pid, inode, time) values (?, ?, ?, ?, ?, ?)")

	if err != nil {
		return err
	}

	insert_tcp_conn, err := db.Prepare("INSERT INTO tcp_conn (sl, localAddr, localPort, remAddr, remPort, st, txQueue, rxQueue, uid, inode) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")

	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	for _, pidConn := range *pidConns {
		// insert parent-pids
		for idx, ppid := range pidConn.PidParents {
			_, err = insert_parent_pid.Exec(pidConn.Pid, ppid, len(pidConn.PidParents)-idx)
			if err != nil {
				return err
			}
		}

		// insert process connections
		_, err = insert_process_conn.Exec(pidConn.UserName, pidConn.Command, pidConn.CommandLine, pidConn.Pid, pidConn.Connection.Inode, pidConn.Time.UnixNano())
		if err != nil {
			return err
		}

		// insert tcp connection data
		conn := pidConn.Connection
		_, err = insert_tcp_conn.Exec(conn.SL, conn.LocalAddr.String(), conn.LocalPort, conn.RemAddr.String(), conn.RemPort, conn.St, conn.TxQueue, conn.RxQueue, conn.UID, conn.Inode)
		if err != nil {
			return err
		}
	}

	return nil
}

// Report network information to the console
func ReportNetwork(pidConns *[]PidSocket, store MachineNetworkStorage, json bool) error {
	if json {
		return ReportJSONNetwork(pidConns, store)
	} else {
		return ReportDBNetwork(pidConns, store)
	}
}
