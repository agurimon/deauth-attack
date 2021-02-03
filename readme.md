# deauth-attack

## Usage
```
./deauth-attack <interface> <ap mac> [<station mac>]")

$ sudo ./deauth-attack mon0 00:11:22:33:44:55")
$ sudo ./deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB")
```

## Install
```
$ sudo apt install libpcap-dev gcc -y 
```

## Go GET
```
sudo go get "github.com/google/gopacket" \
            "github.com/google/gopacket/layers" \
            "github.com/google/gopacket/pcap"
```