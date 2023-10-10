package listen

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"os"
	"time"

	// "crypto/tls"
	tls "proxy/tls_fork"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

type Listener struct {
	ProxyURL                  string
	StoragePath               string
	ServerSentRecordsFileName string
	ClientSentRecordsFileName string
	DefaultPort               string
	LocalhostPort             string
}

func NewListener() Listener {

	// change for better config management
	return Listener{
		ProxyURL:                  "localhost:8082",
		StoragePath:               "./local_storage/",
		ServerSentRecordsFileName: "ServerSentRecords",
		ClientSentRecordsFileName: "ClientSentRecords",
		DefaultPort:               "443",
		LocalhostPort:             "8081",
	}
}

func (l *Listener) Listen() error {

	// initialize listener
	listener, err := net.Listen("tcp", l.ProxyURL)
	if err != nil {
		log.Error().Err(err).Msg("net.Listen()")
	}
	log.Debug().Msg("start PROXY capturing on " + listener.Addr().String())

	// infinite loop
	for {

		// accept connection
		clientConn, err := listener.Accept()
		if err != nil {
			log.Error().Err(err).Msg("listener.Accept()")
		}
		log.Debug().Msg("connection from " + clientConn.RemoteAddr().String())

		// read deadline for reading clientHello
		if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			log.Error().Err(err).Msg("clientConn.SetReadDeadline")
			return err
		}

		// read clientHello
		clientHello, clientReader, err := peekClientHello(clientConn)
		if err != nil {
			log.Error().Err(err).Msg("peekClientHello(clientConn)")
			return err
		}

		// reset read deadline to default
		if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
			log.Error().Err(err).Msg("clientConn.SetReadDeadline(time.Time{})")
			return err
		}

		// use port 8081 if local setting, default to 443
		port := l.DefaultPort
		domain := clientHello.ServerName
		if domain == "localhost" {
			port = l.LocalhostPort
		}

		// establish connection to SNI domain
		serverConn, err := net.DialTimeout("tcp", net.JoinHostPort(domain, port), 5*time.Second)
		if err != nil {
			log.Error().Err(err).Msg("net.DialTimeout()")
			return err
		}

		// prepare capturing configurations
		serverPath := l.StoragePath + l.ServerSentRecordsFileName
		clientPath := l.StoragePath + l.ClientSentRecordsFileName

		// errorgroup to catch and wait for connections to finish
		g := new(errgroup.Group)

		// pipe incoming traffic from client to destination connection
		g.Go(func() error {
			return pipe(clientConn, serverConn, serverPath)
		})

		// pipe destination server responses to client connection
		g.Go(func() error {
			return pipe(serverConn, clientReader, clientPath)
		})

		// wait until goroutines finish and print any error
		if err := g.Wait(); err != nil {
			log.Error().Err(err).Msg("g.Wait()")
			return err
		}

		// close channels
		defer clientConn.Close()
		defer serverConn.Close()
	}
}

// used to be type: net.Conn
func pipe(dst io.Writer, src io.Reader, path string) error {

	// open files to store captured traffic
	var err error
	fileHandleRaw, err := os.OpenFile(path+".raw", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	fileHandleTxt, err := os.OpenFile(path+".txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer fileHandleRaw.Close()
	defer fileHandleTxt.Close()

	size := 4068 // 32 * 1024 // 4068
	buf := make([]byte, size)

	for {

		// measure time
		start := time.Now()

		// read from connection
		nr, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				// capturing EOF is expected at some point
				return nil
			}
			log.Error().Err(err).Msg("src.Read(buf)")
			break
		}

		// save captured transcript
		bufferWrite(buf[:nr], fileHandleRaw, fileHandleTxt)
		// log.Debug.Msg("record: "+hex.EncodeToString(buf[:nr])+" from "+src.RemoteAddr()+" to "+dst.RemoteAddr()+"\n")

		// write to other connection
		_, err = dst.Write(buf[0:nr])
		if err != nil {
			log.Error().Err(err).Msg("dst.Write(buf[0:nr])")
			return err
		}

		// evaluate time
		elapsed := time.Since(start)
		log.Debug().Str("time", elapsed.String()).Msg("copy cycle time")
	}

	return err
}

// write to fs
func bufferWrite(msg []byte, fileHandleRaw *os.File, fileHandleTxt *os.File) {

	// flush bytes to file
	buf := bufio.NewWriter(fileHandleRaw)
	buf.Write(msg)
	err := buf.Flush()
	if err != nil {
		log.Error().Err(err).Msg("buf.Flush() raw")
	}

	// flush hex string encoded bytes to file
	buf = bufio.NewWriter(fileHandleTxt)
	buf.WriteString(hex.EncodeToString(msg))
	err = buf.Flush()
	if err != nil {
		log.Error().Err(err).Msg("buf.Flush() txt")
	}
}

// Copyright (c) 2020 Andrew Ayer
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

// reader of clientHello
func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}
	return hello, io.MultiReader(peekedBytes, reader), nil
}

// connection io reader
type readOnlyConn struct {
	reader io.Reader
}

// io reader methods
func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

// implements clientHello read
func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}
