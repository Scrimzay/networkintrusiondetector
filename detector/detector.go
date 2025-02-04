package detector

import (
	"strings"
	"time"
	"fmt"

	"github.com/Scrimzay/loglogger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/dgraph-io/badger/v4"
)

var log *logger.Logger

type Detector struct {

}

func NewDetector() *Detector {
	return &Detector{

	}
}

// processes a packet and checks for intrusions
func (d *Detector) AnalyzePacket(packet gopacket.Packet, db *badger.DB, blockIP func(string)) {
    if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
        payload := string(applicationLayer.Payload())
        if strings.Contains(payload, "' OR '1'='1") {
            d.Alert(packet, "Intrusion detected: SQL injection attempt", db, blockIP)
        }
        if strings.Contains(payload, "<script>") {
            d.Alert(packet, "Intrusion detected: XSS attempt", db, blockIP)
        }
    }
}

func (d *Detector) Alert(packet gopacket.Packet, message string, db *badger.DB, blockIP func(string)) {
    var srcIP string
    if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)
        srcIP = ip.SrcIP.String()
    }

	log, _ = logger.New("alert.txt")
    log.Printf("ALERT: %s\nSource IP: %s\nPayload: %s\n", message, srcIP, string(packet.ApplicationLayer().Payload()))
    logIntrusion(db, packet, message)
    blockIP(srcIP)
}

func logIntrusion(db *badger.DB, packet gopacket.Packet, message string) {
    var srcIP, dstIP string
    if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)
        srcIP = ip.SrcIP.String()
        dstIP = ip.DstIP.String()
    }

    payload := ""
    if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
        payload = string(applicationLayer.Payload())
    }

    // Create a unique key for the intrusion log
    key := []byte(time.Now().Format(time.RFC3339Nano))

    // Create a value for the intrusion log
    value := fmt.Sprintf(
        "Source IP: %s\nDestination IP: %s\nPayload: %s\nMessage: %s",
        srcIP,
        dstIP,
        payload,
        message,
    )

	log, _ = logger.New("intrusions.txt")
    // Store the intrusion log in BadgerDB
    err := db.Update(func(txn *badger.Txn) error {
		log.Print("Intrusion detected stored: %s", value)
        return txn.Set(key, []byte(value))
    })
    if err != nil {
        log.Printf("Failed to log intrusion: %v\n", err)
    }
}