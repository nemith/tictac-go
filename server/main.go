package main

import (
	"fmt"
	"net"
	"tictac"
)

func main() {

	ln, err := net.Listen("tcp", ":4900")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error!")
			continue
		}
		s := tictac.NewSession(conn)
		go s.Handle()
	}

}
