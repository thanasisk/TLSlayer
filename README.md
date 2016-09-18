[![Go Report Card](https://goreportcard.com/badge/github.com/thanasisk/TLSlayer)](https://goreportcard.com/report/github.com/thanasisk/TLSlayer)

# Project Title

TLSlayer is a *FAST* TLS/SSL reconnaisance tool written in Go. The primary aim is to provide a tool that has no dependencies on OpenSSL that can utilize multiple cores.

## Getting Started

git clone and you should be good to go.

### Prerequisities && compilation

A recent version of Golang - in my local machine at the time of writing I used

```
go build
```

### Usage

```
Usage of ./TLSlayer:
-db string
external cipher suite database. DB Format: cipherID,name,protocol,Kx,Au,Enc,Bits,Mac,Auth Strength,Enc Strength,Overall Strength
THIS IS NOT NEEDED as ciphers.go contain already 350+ cipher suites
-debug
turn on debugging output - developer usage only
-fuzz
wanna fuzz? Enable this
-host string
hostname to test (default "localhost")
-perf int
size of worker pool (default 8) - feel free to experiment
-port string
port to connect (default "443")
-verbose
verbosity status, silent by default
Using the following switches you can enable/disable handshakes
-ssl2
SSL2 handshake
-ssl3
SSL3 handshake
-tls1
TLS 1.0 handshake
-tls11
TLS 1.1 handshake
-tls12
TLS 1.2 handshake
-tls13
TLS 1.3 handshake

By default, -ssl3, tls1 are enabled
```

And repeat

```
Below is a test run against twitter.com

$ ./TLSlayer -host twitter.com -tls12
[TLS v1.2] TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0x00C02F)
[TLS v1.2] TLS_RSA_WITH_AES_256_GCM_SHA384 (0x00009D)
[TLS v1.2] TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0x00C030)
[TLS v1.2] TLS_RSA_WITH_AES_256_CBC_SHA (0x000035)
[TLS v1.2] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0x00C027)
[TLS v1.2] TLS_RSA_WITH_AES_128_CBC_SHA256 (0x00003C)
[TLS v1.2] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0x00C013)
[TLS v1.2] TLS_RSA_WITH_AES_128_CBC_SHA (0x00002F)
[TLS v1.2] TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0x00C014)
[TLS v1.2] TLS_RSA_WITH_AES_128_GCM_SHA256 (0x00009C)
[TLS v1.2] TLS_RSA_WITH_AES_256_CBC_SHA256 (0x00003D)
[TLS v1.2] TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0x00C012)
[TLS v1.2] TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x00000A)
[TLS v1.2] TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0x00C028)

```


## Running the tests

No tests so far, contributions are more than welcome.

### Break down into end to end tests

See above.

### And coding style tests

Always use go vet, go fmt and go lint - check out the report card on top.

## Deployment

The static binary has no dependencies.

## Built With

* Golang 1.7.1
* vim

## Contributing

1. Fork it 
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -sm 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## Authors

* **Athanasios Kostopoulos** - *Initial work* - [thanasisk](https://github.com/thanasisk)


## License

This project is licensed under the GPL v3 License

## Acknowledgments

* iphelix for original sslmapper.py
* Spatially for their go-workgroup implementation (need to fix the comments though)
* Dr_Ciphers for helping out with testing


