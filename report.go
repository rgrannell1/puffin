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

const CREATE_UDP_CONN_TABLE = `create table if not exists udp_conn (
	sl        integer,
	localAddr text,
	remAddr   text,
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

const CREATE_CONN_SUMMARY_TABLE = `create table if not exists conn_summary (
	device  text,
	localAddr text,
	localPort integer,
	remAddr   text,
	remPort   integer,
  size    int,
	start   int,
	end     int
)`

const CREATE_PACKET_TABLE = `create table if not exists packet (
	device  text,
	localAddr text,
	localPort integer,
	remAddr   text,
	remPort   integer,
	size      integer,
  time      integer
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
		CREATE_UDP_CONN_TABLE,
		CREATE_PROCCESS_CONN_TABLE,
		CREATE_PID_PARENTS_TABLE,
		CREATE_CONN_SUMMARY_TABLE,
		CREATE_PACKET_TABLE,
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

	insert_udp_conn, err := db.Prepare("INSERT INTO udp_conn (sl, localAddr, remAddr, st, txQueue, rxQueue, uid, inode) values (?, ?, ?, ?, ?, ?, ?, ?)")

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
		_, err = insert_process_conn.Exec(pidConn.UserName, pidConn.Command, pidConn.CommandLine, pidConn.Pid, pidConn.Connection.Inode(), pidConn.Time.UnixNano())
		if err != nil {
			return err
		}

		// TODO if tcp, use switch to handle insert

		// insert tcp connection data
		conn := pidConn.Connection

		switch conn.GetType() {
		case "TCP":
			conn := conn.(TCPConnection)

			// insert into TCP table
			_, err = insert_tcp_conn.Exec(
				conn.SL(),
				conn.LocalAddr().String(),
				conn.LocalPort(),
				conn.RemAddr().String(),
				conn.RemPort(),
				conn.ST(),
				conn.TxQueue(),
				conn.RxQueue(),
				conn.UID(),
				conn.Inode())

			if err != nil {
				return err
			}
		case "UDP":
			conn := conn.(UDPConnection)

			// insert into TCP table
			_, err = insert_udp_conn.Exec(
				conn.SL(),
				conn.LocalAddr().String(),
				conn.RemAddr().String(),
				conn.ST(),
				conn.TxQueue(),
				conn.RxQueue(),
				conn.UID(),
				conn.Inode())

			if err != nil {
				return err
			}
		}
	}

	insert_conn_summary, err := db.Prepare("INSERT INTO conn_summary (device, localAddr, localPort, remAddr, remPort, size, start, end) values (?, ?, ?, ?, ?, ?, ?, ?)")

	if err != nil {
		return err
	}

	insert_packet, err := db.Prepare("INSERT INTO packet (device, localAddr, localPort, remAddr, remPort, size, time) values (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}

	// add packet information to database
	for device, conns := range store {
		for _, connData := range conns {
			_, err := insert_conn_summary.Exec(device, connData.LocalAddr.String(), connData.LocalPort, connData.RemAddr.String(), connData.RemPort, connData.Size, connData.From, connData.To)

			if err != nil {
				return err
			}

			for _, pkt := range connData.Packets {
				_, err := insert_packet.Exec(device, connData.LocalAddr.String(), connData.LocalPort, connData.RemAddr.String(), connData.RemPort, pkt.Size, pkt.Timestamp)

				if err != nil {
					return err
				}
			}
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
