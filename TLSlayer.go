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

func loadCiphersFromFile(db string) map[string]Cipher {
	var ciphers map[string]Cipher
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
		cipher := Cipher{
			id:               record[0],
			name:             record[1],
			protocol:         record[2],
			kx:               record[3],
			au:               record[4],
			enc:              record[5],
			bits:             record[6],
			mac:              record[7],
			kxau_strength:    record[8],
			enc_strength:     record[9],
			overall_strength: record[10],
		}
		ciphers[record[0]] = cipher
	}
	return ciphers
}

func printCipher(cipherID string) {
	cipherID = strings.ToUpper(cipherID)
	if _, ok := ciphers[cipherID]; ok {
		fmt.Printf("[+] %s (0x%s)\n", ciphers[cipherID].name, cipherID)
		if verbose {
			fmt.Printf("    Specs: Kx=%s, Au=%s, Enc=%s, Bits=%s, Mac=%s\n", ciphers[cipherID].kx, ciphers[cipherID].au, ciphers[cipherID].enc, ciphers[cipherID].bits, ciphers[cipherID].mac)
			fmt.Printf("    Score: Kx/Au=%s, Enc/MAC=%s, Overall=%s\n", ciphers[cipherID].kxau_strength, ciphers[cipherID].enc_strength, ciphers[cipherID].overall_strength)
		}
	} else {
		fmt.Printf("[+] Undocumented cipher (0x%s)\n", cipherID)
	}
}

func checkCipher(id string, host string, port string, handshake string) bool {
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

func fuzzCiphers(host string, port string, handshakes []string) {
	var cipherID string
	fmt.Printf("[*] Fuzzing %s:%s for ALL possible cipher suite IDs\n", host, port)
	for _, handshake := range handshakes {
		if verbose {
			fmt.Printf("[*] Using %s handshake ...\n", handshake)
		}
		fmt.Printf("[-] Generating jobs\n")
		for i := 0; i < 16777215; i++ {
			cipherID = fmt.Sprintf("%06x", i)
			if debug {
				fmt.Printf("cipherID %s\n", cipherID)
			}
			if checkCipher(cipherID, host, port, handshake) {
				printCipher(cipherID)
			}
		}
	}
}

func knownCiphers(host string, port string, handshakes []string) {
	fmt.Printf("[*] Scanning %s:%s for %d known cipher suites\n", host, port, len(ciphers))
	for _, handshake := range handshakes {
		if verbose {
			fmt.Printf("[*] Using %s handshake\n", handshake)
		}
		for cipherID := range ciphers {
			if checkCipher(cipherID, host, port, handshake) {
				printCipher(cipherID)
			}
		}
	}
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
		ciphers = loadCiphersFromFile(*dbPtr)
	}
	if *verbosePtr {
		verbose = true
	}
	if *debugPtr {
		debug = true
	}
	fmt.Println(*hostPtr, *portPtr, *fuzzPtr)
	// This is a Worker function. The workgroup will start however many of these
	// you specify.
	workhorse := func(worker int, work Work) {
		//handshake := <-out
		log.Printf("workgroup: worker %d handing work %d.", worker, work)
	}

	// This is a Work-Generator. It simply feeds work to each Worker goroutine
	// as each is ready for Work. Although the Workers are goroutines, a
	// workgroup uses sync.WaitGroup interanlly so this goroutine will block
	// on the out channel until a Worker reads from the channel.
	// The completion of this signals the workgroup's cleanup process (all the
	// Workers will complete their work.)
	workUnits := Generator(func(out chan<- Work) {
		// TODO: fill me in
	})
	// can also specify =< 0
	FanOut(*perfPtr).Drain(workUnits).With(workhorse).Go()
}
