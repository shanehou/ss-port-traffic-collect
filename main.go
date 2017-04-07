package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DBConfig struct {
	Host     string
	Protocol string
	User     string
	Password string
	Dbname   string
}

type Config struct {
	Workingdir string
	Ssconfig   string
	Log        string
	Tempdir    string
	Db         *DBConfig
}

type ShadowsocksConfig struct {
	Port_password interface{}
}

var (
	ErrorLogger *log.Logger
	TraceLogger *log.Logger
	db          *sql.DB
	config      *Config
)

func InitLoggers(log_file io.Writer) {
	log_writer := io.MultiWriter(os.Stdout, log_file)
	ErrorLogger = log.New(log_writer, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	TraceLogger = log.New(log_writer, "TRACE: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func ParseShadowsocksConfig(conf_path string) []int {
	ports := make([]int, 0, 20)
	conf_content, err := ioutil.ReadFile(conf_path)
	if err != nil {
		ErrorLogger.Fatalf("open %+v failed: %+v\n", conf_path, err.Error())
	}
	var user_conf ShadowsocksConfig
	err = json.Unmarshal(conf_content, &user_conf)
	if err != nil {
		ErrorLogger.Fatalf("unmarshal shadowsocks config failed: %+v, config: %+v\n", err.Error(), conf_content)
	}
	m := user_conf.Port_password.(map[string]interface{})
	for k, _ := range m {
		port, err := strconv.Atoi(k)
		if err != nil {
			ErrorLogger.Printf("parse port number %+v failed: %+v\n", k, err.Error())
			continue
		}
		ports = append(ports, port)
	}
	return ports
}

func GetLocalIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		ErrorLogger.Fatalf("get interface addrs failed: %+v\n", err.Error())
	}
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			if v.IP.IsLoopback() {
				continue
			}
			ip := v.IP.To4()
			if ip == nil {
				TraceLogger.Printf("ip %+v is not IPv4\n", v)
				continue
			}
			return ip.String()
		case *net.IPAddr:
			TraceLogger.Printf("ipaddr: %+v\n", v)
		}
	}
	return ""
}

func AddRule(port int, ip string) bool {
	TraceLogger.Printf("start adding rule on port %+v\n", port)
	rule := []string{"OUTPUT", "-w", "-p", "tcp", "--sport", strconv.Itoa(port)}
	check := exec.Command("iptables", append([]string{"-C"}, rule...)...)
	c_output, err := check.CombinedOutput()
	if err != nil {
		// Will encounter error if the rule doesn't exist
		ErrorLogger.Printf("check iptables rule on port %+v: %+v, %+v\n", port, string(c_output), err.Error())
	}
	if len(c_output) > 0 {
		add := exec.Command("iptables", append([]string{"-A"}, rule...)...)
		a_output, err := add.CombinedOutput()
		if err != nil {
			ErrorLogger.Printf("add iptables rule on port %+v failed: %+v, %+v\n", port, string(a_output), err.Error())
			return false
		}
		TraceLogger.Printf("added an iptables rule on port %+v\n", port)
		return true
	}
	TraceLogger.Printf("rule on port %+v has already exists\n", port)
	return true
}

func CollectTraffic(port int) (bool, uint64, uint64) {
	TraceLogger.Printf("start collecting traffic on port %+v\n", port)
	var traffic_accu uint64
	var traffic_diff uint64
	traffic_accu = 0
	traffic_diff = 0

	// Collect accumulated traffic
	cmd := "iptables -vnL -t filter -w -x | grep spt:" + strconv.Itoa(port) + "$ | awk '{print $2}'"
	collect := exec.Command("bash", "-c", cmd)
	output, err := collect.CombinedOutput()
	current := strings.Trim(string(output), "\n\t ")
	if err != nil {
		ErrorLogger.Printf("collect accumulated traffic on port %+v failed: %+v, %+v\n", port, current, err.Error())
		return false, traffic_accu, traffic_diff
	}
	traffic_accu, err = strconv.ParseUint(current, 10, 64)
	if err != nil {
		ErrorLogger.Printf("convert iptables traffic %+v to uint64 failed: %+v\n", current, err.Error())
		return false, traffic_accu, traffic_diff
	}
	TraceLogger.Printf("accumulated traffic on port %+v: %+v\n", port, traffic_accu)

	// Collect differential traffic
	portfile, err := os.OpenFile(config.Tempdir+strconv.Itoa(port), os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		ErrorLogger.Printf("open last traffic file %+v failed: %+v\n", port, err.Error())
		return false, traffic_accu, traffic_diff
	}
	defer portfile.Close()
	portstr, err := ioutil.ReadAll(portfile)
	if err != nil {
		ErrorLogger.Printf("read last traffic file %+v failed: %+v\n", port, err.Error())
		return false, traffic_accu, traffic_diff
	}
	last := strings.Trim(string(portstr), "\n\t ")
	var traffic_last uint64
	if len(last) == 0 {
		TraceLogger.Printf("last traffic file %+v is empty\n", port)
		traffic_last = 0
	} else {
		traffic_last, err = strconv.ParseUint(last, 10, 64)
		if err != nil {
			ErrorLogger.Printf("convert last time traffic file content %+v to uint64 failed: %+v\n", last, err.Error())
			return false, traffic_accu, traffic_diff
		}
		TraceLogger.Printf("last traffic file %+v: %+v\n", port, traffic_last)
	}
	// Overwrite current traffic to last traffic file
	if err := ioutil.WriteFile(config.Tempdir+strconv.Itoa(port), []byte(strconv.FormatUint(traffic_accu, 10)), 0644); err != nil {
		ErrorLogger.Printf("write last traffic file failed: %+v\n", err.Error())
	}
	// Likely that the traffic is reset
	if traffic_last > traffic_accu {
		ErrorLogger.Printf("current accumulated traffic %+v is less than last traffic %+v\n", traffic_accu, traffic_last)
		return true, traffic_accu, traffic_accu
	}
	traffic_diff = traffic_accu - traffic_last
	return true, traffic_accu, traffic_diff
}

func CreateTable(port int) bool {
	if port <= 1024 || port > 49151 {
		ErrorLogger.Printf("port %+v is invalid\n", port)
	}
	table_name := "port_" + strconv.Itoa(port)
	if db == nil {
		ErrorLogger.Printf("database handler is not initialized when creating %+v\n", table_name)
		return false
	}
	TraceLogger.Printf("start creating table %+v\n", table_name)
	stmt, err := db.Prepare(`CREATE TABLE IF NOT EXISTS ` + table_name + ` (
			traffic_accu BIGINT NOT NULL DEFAULT 0,
			traffic_diff BIGINT NOT NULL DEFAULT 0,
			collect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (collect_time)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8`)
	if err != nil {
		ErrorLogger.Printf("prepare create table failed: %+v\n", err.Error())
		return false
	}
	defer stmt.Close()
	_, err = stmt.Exec()
	if err != nil {
		ErrorLogger.Printf("execute create table %+v failed: %+v\n", table_name, err.Error())
		return false
	}
	TraceLogger.Printf("created table %+v\n", table_name)
	return true
}

func RecordTraffic(port int, traffic []uint64) {
	table_name := "port_" + strconv.Itoa(port)
	if db == nil {
		ErrorLogger.Printf("database handler is not initialized when creating %+v\n", table_name)
		return
	}
	if len(traffic) != 2 {
		ErrorLogger.Printf("traffic data is invalid: %+v\n", traffic)
		return
	}
	TraceLogger.Printf("start recording traffic %+v on port %+v\n", traffic, port)
	stmt, err := db.Prepare(`INSERT INTO ` + table_name + ` (traffic_accu, traffic_diff) VALUES (?, ?)`)
	if err != nil {
		ErrorLogger.Printf("prepare insert into failed: %+v\n", err.Error())
		return
	}
	defer stmt.Close()
	result, err := stmt.Exec(traffic[0], traffic[1])
	if err != nil {
		ErrorLogger.Printf("execute insert into %+v failed: %+v\n", table_name, err.Error())
		return
	}
	rows_affected, err := result.RowsAffected()
	if err != nil {
		ErrorLogger.Printf("get affected rows failed: %+v\n", err.Error())
		return
	}
	if rows_affected != 1 {
		ErrorLogger.Printf("affected %+v rows\n", rows_affected)
		return
	}
	TraceLogger.Printf("inserted %+v item (%+v, %+v) in %+v\n", rows_affected, traffic[0], traffic[1], table_name)
}

func ReadConfig(conf_path string) {
	conf, err := ioutil.ReadFile(conf_path)
	if err != nil {
		log.Fatalf("read config file %+v failed: %+v\n", conf_path, err.Error())
	}
	err = json.Unmarshal(conf, &config)
	if err != nil {
		log.Fatalf("unmarshal config file %+v failed: %+v, config file: %+v\n", conf_path, err.Error(), string(conf))
	}
	log.Printf("config: %+v\n", config)
}

func main() {
	log.Printf("$PATH: %+v\n", os.Getenv("PATH"))
	// Read global config
	ReadConfig("config.json")
	if config == nil {
		log.Fatalln("config file not read")
	}

	// Change working directory for log and cache files
	if err := os.Chdir(config.Workingdir); err != nil {
		log.Fatalf("change working directory to %+v failed: %+v\n", config.Workingdir, err.Error())
	}

	// Init log files
	log_file, err := os.OpenFile(config.Log, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("open error log file failed: %+v\n", err.Error())
	}
	defer log_file.Close()
	InitLoggers(log_file)

	// Start main logic
	start := time.Now()

	// Create directory for last traffic file
	if err := os.MkdirAll(config.Tempdir, 0755); err != nil {
		ErrorLogger.Fatalf("create directory %+v failed: %+v\n", config.Tempdir, err.Error())
	}

	// Connect database
	dsn := fmt.Sprintf("%s:%s@%s(%s)/%s", config.Db.User, config.Db.Password, config.Db.Protocol, config.Db.Host, config.Db.Dbname)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		ErrorLogger.Fatalf("open database handle failed: %+v, dsn: %+v\n", err.Error(), dsn)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		ErrorLogger.Fatalf("ping database failed: %+v\n", err.Error())
	}

	// Read and parse shadowsocks config
	ports := ParseShadowsocksConfig(config.Ssconfig)
	TraceLogger.Printf("port list: %+v\n", ports)

	// Cocurrently collect and save traffic data
	local_ip_addr := GetLocalIPAddress()
	TraceLogger.Printf("local ip address: %+v\n", local_ip_addr)

	// Prevent early exit
	var final sync.WaitGroup
	final.Add(len(ports))
	// Store the traffic data
	traffic := make(map[int][]uint64)
	// Lock-free status map
	st1 := make(map[int]bool)
	st2 := make(map[int]bool)
	for _, port := range ports {
		var wg sync.WaitGroup
		wg.Add(2)
		st1[port] = true
		st2[port] = true
		go func(port int, wg *sync.WaitGroup) {
			defer wg.Done()
			if !st1[port] {
				return
			}
			// Add iptables rules (if not exist), and save the config
			if !AddRule(port, local_ip_addr) {
				st1[port] = false
				return
			}
			// Get ports' traffic data by iptables
			ok, traffic_accu, traffic_diff := CollectTraffic(port)
			if !ok {
				st1[port] = false
				return
			}
			traffic[port] = append(traffic[port], traffic_accu, traffic_diff)
		}(port, &wg)
		// Create tables (if not exist) according to the port numbers in /etc/shadowsocks.json
		go func(port int, wg *sync.WaitGroup) {
			defer wg.Done()
			if !st2[port] {
				return
			}
			if !CreateTable(port) {
				st2[port] = false
				return
			}
		}(port, &wg)
		go func(port int, wg *sync.WaitGroup) {
			defer final.Done()
			wg.Wait()
			if !st1[port] || !st2[port] {
				ErrorLogger.Printf("Adding rule and collecting data: %+v, Creating table: %+v\n", st1[port], st2[port])
				return
			}
			// Calculate traffic difference using a local cache file, and insert all data to corresponding tables
			RecordTraffic(port, traffic[port])
		}(port, &wg)
	}
	final.Wait()

	save := exec.Command("iptables-save")
	err = save.Run()
	if err != nil {
		ErrorLogger.Printf("save iptables rules failed: %+v\n", err.Error())
	}

	TraceLogger.Printf("all done in %+v\n", time.Since(start))
}
