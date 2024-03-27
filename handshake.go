package tls_sni

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	tls "github.com/refraction-networking/utls"
	"math/big"
	"net"
	"time"
	"unsafe"
)

type hostConn struct {
	h string
	net.Conn
	handled bool
}

func (c *hostConn) Write(b []byte) (n int, err error) {
	if !c.handled {
		hlen := len(c.h)
		if hostIndex := bytes.Index(b, unsafe.Slice(unsafe.StringData(c.h), hlen)); hostIndex > 0 {
			c.handled = true
			var wn int
			rn, _ := rand.Int(rand.Reader, big.NewInt(int64(hlen)))
			wp := hostIndex + int(rn.Int64())
			wn, err = c.Conn.Write(b[0:wp])
			fmt.Println(hostIndex, wp)
			if err != nil {
				return 0, err
			}
			n += wn
			time.Sleep(sleepTime)
			wn, err = c.Conn.Write(b[wp:])
			n += wn
			return
		}
	}

	return c.Conn.Write(b)
}

var minLength = 10000
var sleepTime = time.Millisecond * 200

func SetMinLengthAndSleepTime(m int, s time.Duration) {
	if m > minLength {
		minLength = m
	}
	sleepTime = s
}

func HandleShakeContext(c net.Conn, host string, ctx context.Context, tlsConfig *tls.Config, spec *tls.ClientHelloSpec) (net.Conn, error) {
	hc := &hostConn{host, c, false}
	uTlsConn := tls.UClient(hc, tlsConfig, tls.HelloCustom)
	b := make([]byte, 1)
	rand.Read(b)
	randLen := minLength + int(b[0])
	spec.Extensions = append(spec.Extensions, &tls.UtlsPaddingExtension{GetPaddingLen: func(clientHelloUnpaddedLen int) (paddingLen int, willPad bool) {
		paddingLen = randLen - clientHelloUnpaddedLen
		if paddingLen > 0 {
			willPad = true
		}
		return
	}})
	err := uTlsConn.ApplyPreset(spec)
	if err != nil {
		return nil, err
	}

	err = uTlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}
	return uTlsConn, nil
}
