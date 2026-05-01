package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	ifname := envOr("WG_IFNAME", "wg0")
	configFile := envOr("WG_CONFIG", "/tmp/wg.conf")
	readyFile := os.Getenv("WG_READY_FILE")
	daitaPeerHex := os.Getenv("DAITA_PEER_HEX")
	daitaMachinesFile := os.Getenv("DAITA_MACHINES_FILE")

	tunDev, err := tun.CreateTUN(ifname, 1420)
	if err != nil {
		log.Fatalf("create tun: %v", err)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", ifname))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	// Apply UAPI configuration (wg setconf format: private_key=, listen_port=, public_key=, ...)
	confData, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("read config %s: %v", configFile, err)
	}
	if err := dev.IpcSetOperation(strings.NewReader(string(confData))); err != nil {
		log.Fatalf("ipc set: %v", err)
	}

	dev.Up()

	// Serve UAPI socket so `wg show` works from entrypoint scripts
	uapiSocket, err := ipc.UAPIOpen(ifname)
	if err != nil {
		log.Fatalf("uapi open: %v", err)
	}
	uapiListener, err := ipc.UAPIListen(ifname, uapiSocket)
	if err != nil {
		log.Fatalf("uapi listen: %v", err)
	}
	go func() {
		for {
			c, err := uapiListener.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	// Enable DAITA on the specified peer
	if daitaPeerHex != "" && daitaMachinesFile != "" {
		machinesData, err := os.ReadFile(daitaMachinesFile)
		if err != nil {
			log.Fatalf("read machines: %v", err)
		}

		var pubkey device.NoisePublicKey
		b, err := hex.DecodeString(strings.TrimSpace(daitaPeerHex))
		if err != nil || len(b) != 32 {
			log.Fatalf("invalid DAITA_PEER_HEX: %v", err)
		}
		copy(pubkey[:], b)

		peer := dev.LookupPeer(pubkey)
		if peer == nil {
			log.Fatalf("peer %s not found after config", daitaPeerHex)
		}
		machines := strings.TrimSpace(string(machinesData))
		if !peer.EnableDaita(machines, 1000, 1000, 0.1, 0.0) {
			log.Fatalf("enable daita failed")
		}
		log.Printf("DAITA enabled on peer %s", daitaPeerHex)
	}

	if readyFile != "" {
		f, _ := os.Create(readyFile)
		f.Close()
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	<-term

	uapiListener.Close()
	dev.Close()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
