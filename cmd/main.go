package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	traceroute "github.com/moolen/traceroute"
)

func main() {
	{
		if len(os.Args) < 2 {
			fmt.Println("invalid arguments. usage: traceroute [hostname]")
			os.Exit(1)
		}
		addrs, err := net.LookupIP(os.Args[1])
		if err != nil {
			panic(err)
		}
		for _, addr := range addrs {
			if len(addr) == 4 {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
				defer cancel()
				hops, err := traceroute.TraceWithTTL(ctx, addr, 32)
				if err != nil {
					fmt.Println(err.Error())
					os.Exit(1)
				}
				for _, hop := range hops {
					fmt.Printf("[%d] %s [%s]\n", hop.TTL, hop.IP, strings.Join(hop.Names, ","))
				}
			}
		}
	}
}
