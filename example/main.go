package main

import (
	"client-cdn/tls_sni"
	"context"
	gotls "crypto/tls"
	"fmt"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"net"
	"net/http"
	"time"
)

func main() {

	c, err := net.DialTimeout("tcp", "185.15.58.224:443", time.Second*3)
	if err != nil {
		fmt.Println(err)
		return
	}
	var host = "www.wikipedia.org"
	spec, _ := tls.UTLSIdToSpec(tls.HelloChrome_120)
	ctx, _ := context.WithTimeout(context.Background(), time.Second*5)
	tls_sni.SetMinLengthAndSleepTime(16000, time.Millisecond*500)
	tlsConn, err := tls_sni.HandleShakeContext(c, host, ctx, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}, &spec)
	if err != nil {
		fmt.Println(err)
		return
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+host, nil)
	httpClient := &http.Client{Transport: &http2.Transport{DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
		return tlsConn, nil
	}}}
	res, err := httpClient.Do(req)
	fmt.Println(res, err)
}
