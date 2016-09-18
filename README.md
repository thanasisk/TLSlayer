[![Go Report Card](https://goreportcard.com/badge/github.com/thanasisk/TLSlayer)](https://goreportcard.com/report/github.com/thanasisk/TLSlayer)

TLSlayer is a TLS/SSL reconnaisance tool written in Go. The primary aim is to provide a tool that has no dependencies on OpenSSL. The main ideas are based on iphelix's sslmap.py. Given that it is written in Golang, it supports multiple cores via the use of wg.go (shamelessy stolen) which leads to a considerable performance increase.
Empirical testing on my machine shows 700% speed increase, however YMMV.


