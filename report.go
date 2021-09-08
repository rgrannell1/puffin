package main

import (
	"encoding/json"
	"fmt"
)

// Report network information to the console
func ReportNetwork(pidConns *[]PidSocket, store MachineNetworkStorage) {
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
						fmt.Println(err)
					}

					fmt.Println(string(bytes))
				}
			}
		}
	}
}
