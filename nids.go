package main

import (
	"net/http"
	"github.com/Scrimzay/nids/detector"
	"github.com/Scrimzay/nids/server"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
	"os"
	"bufio"
	"regexp"

	"github.com/Scrimzay/loglogger"
	"github.com/dgraph-io/badger/v4"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var log *logger.Logger

func initDB() *badger.DB {
	var err error
	log, err = logger.New("details.txt")
	if err != nil {
		log.Fatalf("Error starting new logger: %v", err)
	}

    // Open the Badger database
    db, err := badger.Open(badger.DefaultOptions("./badgerdb").WithLogger(nil))
    handleFatalErr(err)

    // Schedule periodic garbage collection
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()
        for range ticker.C {
            for db.RunValueLogGC(0.5) == nil {
            }
        }
    }()

    return db
}

func main() {
	db := initDB()
	defer db.Close()

	go server.RunServer()
	go setupAPI(db)
	go setupLogViewer()
	
	devices, err := pcap.FindAllDevs()
	handleFatalErr(err)

	deviceName := devices[5].Name 
	// open device
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	handleFatalErr(err)
	defer handle.Close()

	// set filter (optional)
	err = handle.SetBPFFilter("tcp and port 8080")
	handleFatalErr(err)

	det := detector.NewDetector()

	// read packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		det.AnalyzePacket(packet, db, blockIP)
	}
}

func setupAPI(db *badger.DB) {
    r := gin.Default()

    r.GET("/intrusions", func(c *gin.Context) {
        var logs []string
        err := db.View(func(txn *badger.Txn) error {
            opts := badger.DefaultIteratorOptions
            it := txn.NewIterator(opts)
            defer it.Close()

            for it.Rewind(); it.Valid(); it.Next() {
                item := it.Item()
                err := item.Value(func(val []byte) error {
                    logs = append(logs, string(val))
                    return nil
                })
                if err != nil {
                    return err
                }
            }
            return nil
        })
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, logs)
    })

    r.Run(":8081")
}

type LogEntry struct {
	Timestamp time.Time
	Message string
}

func setupLogViewer() {
	r :=gin.Default()
	r.LoadHTMLGlob("*.html")
	r.Static("/static", "./static")

	r.GET("/details", handleDetailsViewer)
	r.GET("/alerts", handleAlertsViewer)
	r.GET("/intrusions", handleIntrusionsViewer)

	r.Run(":8082")
}

// ParseLogs reads a log file and groups entries by 5-minute intervals
func ParseLogs(filePath string) (map[string][]LogEntry, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    logs := make(map[string][]LogEntry)
    scanner := bufio.NewScanner(file)

    // Regex to extract timestamp and message
    re := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) (.*)`)

    for scanner.Scan() {
        line := scanner.Text()
        matches := re.FindStringSubmatch(line)
        if len(matches) < 3 {
            continue // Skip malformed lines
        }

        timestampStr := matches[1]
        message := matches[2]

        // Parse the timestamp
        timestamp, err := time.Parse("2006/01/02 15:04:05", timestampStr)
        if err != nil {
            continue // Skip lines with invalid timestamps
        }

        // Round the timestamp to the nearest 5-minute interval
        interval := timestamp.Truncate(5 * time.Minute).Format("2006-01-02 15:04")

        // Add the log entry to the corresponding interval
        logs[interval] = append(logs[interval], LogEntry{Timestamp: timestamp, Message: message})
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return logs, nil
}

func handleDetailsViewer(c *gin.Context) {
	// get the current date log folder
	dateFolder := time.Now().Format("2006-01-02")
	logFilePath := filepath.Join("logs", dateFolder, "details.txt")

	// parse the logs
	logs, err := ParseLogs(logFilePath)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to read logs: %v", err)
		return
	}

	// sort intervals in descending order
	var intervals []string
	for interval := range logs {
		intervals = append(intervals, interval)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(intervals)))

	c.HTML(200, "logDetails.html", gin.H{
		"LogType": "details",
		"Intervals": intervals,
		"Logs": logs,
	})
}

func handleAlertsViewer(c *gin.Context) {
	dateFolder := time.Now().Format("2006-01-02")
    logFilePath := filepath.Join("logs", dateFolder, "alert.txt")

    logs, err := ParseLogs(logFilePath)
    if err != nil {
        c.String(http.StatusInternalServerError, "Failed to read logs: %v", err)
        return
    }

    var intervals []string
    for interval := range logs {
        intervals = append(intervals, interval)
    }
    sort.Sort(sort.Reverse(sort.StringSlice(intervals)))

    c.HTML(http.StatusOK, "logAlerts.html", gin.H{
        "LogType":   "alerts",
        "Intervals": intervals,
        "Logs":      logs,
    })
}

func handleIntrusionsViewer(c *gin.Context) {
	dateFolder := time.Now().Format("2006-01-02")
    logFilePath := filepath.Join("logs", dateFolder, "intrusions.txt")

    logs, err := ParseLogs(logFilePath)
    if err != nil {
        c.String(http.StatusInternalServerError, "Failed to read logs: %v", err)
        return
    }

    var intervals []string
    for interval := range logs {
        intervals = append(intervals, interval)
    }
    sort.Sort(sort.Reverse(sort.StringSlice(intervals)))

    c.HTML(http.StatusOK, "logIntrusions.html", gin.H{
        "LogType":   "intrusions",
        "Intervals": intervals,
        "Logs":      logs,
    })
}

func handleFatalErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func blockIP(ip string) {
    cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
    if err := cmd.Run(); err != nil {
        log.Printf("Failed to block IP %s: %v\n", ip, err)
    } else {
        log.Printf("Blocked IP: %s\n", ip)
    }
}