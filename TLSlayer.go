package main

import "flag"
import "os"
import "fmt"
import "encoding/csv"
import "encoding/hex"
import "bufio"
import "log"
import "io"
import "net"
import "reflect"
import "strings"

var pkts = make(map[string][]byte)
var challenge []byte

var verbose bool
var debug bool

func init() {
	pkts["TLS v1.3"] = []byte("\x80\x2c\x01\x03\x04\x00\x03\x00\x00\x00\x20")
	pkts["TLS v1.2"] = []byte("\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20")
	pkts["TLS v1.1"] = []byte("\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20")
	pkts["TLS v1.0"] = []byte("\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20")
	pkts["SSL v3.0"] = []byte("\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20")
	pkts["SSL v2.0"] = []byte("\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20")
	// it is all \x00s anyway
	challenge = make([]byte, 32)
}

func loadciphersFromFile(db string) map[string]cipher {
	var ciphers map[string]cipher
	// we have already verified that db exists
	f, err := os.Open(db)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(bufio.NewReader(f))
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		cipher := cipher{
			id:              record[0],
			name:            record[1],
			protocol:        record[2],
			kx:              record[3],
			au:              record[4],
			enc:             record[5],
			bits:            record[6],
			mac:             record[7],
			kxauStrength:    record[8],
			encStrength:     record[9],
			overallStrength: record[10],
		}
		ciphers[record[0]] = cipher
	}
	return ciphers
}

func printCipher(cipherID string, handshake string) {
	cipherID = strings.ToUpper(cipherID)
	fmt.Printf("[%s] ", handshake)
	if _, ok := ciphers[cipherID]; ok {
		fmt.Printf("%s (0x%s)\n", ciphers[cipherID].name, cipherID)
		if verbose {
			fmt.Printf("    Specs: Kx=%s, Au=%s, Enc=%s, Bits=%s, Mac=%s\n", ciphers[cipherID].kx, ciphers[cipherID].au, ciphers[cipherID].enc, ciphers[cipherID].bits, ciphers[cipherID].mac)
			fmt.Printf("    Score: Kx/Au=%s, Enc/MAC=%s, Overall=%s\n", ciphers[cipherID].kxauStrength, ciphers[cipherID].encStrength, ciphers[cipherID].overallStrength)
		}
	} else {
		fmt.Printf(" Undocumented cipher (0x%s)\n", cipherID)
	}
}

func checkCipher(id string, host string, port string, handshake string) bool {
	if debug {
		fmt.Printf("[-] Using handshake %s\n", handshake)
	}
	tlsHello := []byte("\x16")
	tlsAlert := []byte("\x15")
	ssl2Hello := []byte("\x00\x03")
	state := false
	handshakePkt := pkts[handshake]
	if debug {
		fmt.Println(handshake)
		fmt.Println("pkt: " + hex.EncodeToString(handshakePkt))
	}
	if debug {
		fmt.Printf("id: %s\n", id)
	}
	cipher, err := hex.DecodeString(id)
	if err != nil {
		log.Fatal("Could not decode id " + id)
	}
	connStr := host + ":" + port
	conn, err := net.Dial("tcp", connStr)
	if err != nil {
		log.Fatal(err)
	}
	ehlo := append(handshakePkt, (cipher)...)
	ehlo = append(ehlo, challenge...)
	conn.Write(ehlo)
	data := make([]byte, 1)
	tmp := make([]byte, 8)
	ssl2Data := make([]byte, 2)
	conn.Read(data)
	if reflect.DeepEqual(data, tlsHello) {
		state = true
	} else if reflect.DeepEqual(data, tlsAlert) {
		state = false
	} else {
		// we are now is SSLv2 territory!
		conn.Read(tmp)
		conn.Read(ssl2Data)
		if reflect.DeepEqual(ssl2Data, ssl2Hello) {
			state = true
		}
	}
	conn.Close()
	return state
}

func main() {

	hostPtr := flag.String("host", "localhost", "hostname to test")
	portPtr := flag.String("port", "443", "port to connect")
	fuzzPtr := flag.Bool("fuzz", false, "wanna fuzz")
	tls1Ptr := flag.Bool("tls1", false, "TLS 1.0 handshake")
	tls11Ptr := flag.Bool("tls11", false, "TLS 1.1 handshake")
	tls12Ptr := flag.Bool("tls12", false, "TLS 1.2 handshake")
	tls13Ptr := flag.Bool("tls13", false, "TLS 1.3 handshake")
	ssl3Ptr := flag.Bool("ssl3", false, "SSL3 handshake")
	ssl2Ptr := flag.Bool("ssl2", false, "SSL2 handshake")
	verbosePtr := flag.Bool("verbose", false, "verbosity status")
	dbPtr := flag.String("db", "", "external cipher suite database. DB Format: cipherID,name,protocol,Kx,Au,Enc,Bits,Mac,Auth Strength,Enc Strength,Overall Strength")
	debugPtr := flag.Bool("debug", false, "turn on debugging output")
	perfPtr := flag.Int("perf", 8, "size of worker pool")
	flag.Parse()
	handshakes := make([]string, 0)
	if *tls13Ptr {
		handshakes = append(handshakes, "TLS v1.3")
	}
	if *tls12Ptr {
		handshakes = append(handshakes, "TLS v1.2")
	}
	if *tls11Ptr {
		handshakes = append(handshakes, "TLS v1.1")
	}
	if *tls1Ptr {
		handshakes = append(handshakes, "TLS v1.0")
	}
	if *ssl3Ptr {
		handshakes = append(handshakes, "SSL v3.0")
	}
	if *ssl2Ptr {
		handshakes = append(handshakes, "SSL v2.0")
	}
	if len(handshakes) == 0 {
		fmt.Printf("[*] Using baseline handshakes\n")
		handshakes = append(handshakes, "TLS v1.0")
		handshakes = append(handshakes, "SSL v3.0")
	}
	if *dbPtr != "" {
		if _, err := os.Stat(*dbPtr); err != nil {
			fmt.Printf("DB %s not found - exiting\n", *dbPtr)
		}
		ciphers = loadciphersFromFile(*dbPtr)
	}
	if *verbosePtr {
		verbose = true
	}
	if *debugPtr {
		debug = true
	}
	workhorse := func(worker int, work Work) {
		for _, handshake := range handshakes {
			if checkCipher(fmt.Sprint(work), *hostPtr, *portPtr, handshake) {
				printCipher(fmt.Sprint(work), handshake)
			}
		}
	}
	workUnits := Generator(func(out chan<- Work) {
		if *fuzzPtr {
			fmt.Printf("[-] Generating jobs\n")
			for i := 0; i < 16777215; i++ {
				cipherID := fmt.Sprintf("%06x", i)
				out <- cipherID
			}
		} else {
			for cipherID := range ciphers {
				out <- cipherID
			}
		}
	})
	FanOut(*perfPtr).Drain(workUnits).With(workhorse).Go()
}
