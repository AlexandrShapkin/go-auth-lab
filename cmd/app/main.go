package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	HTTPBasicMode = "http_basic_auth"
	CookieMode    = "cookie_auth"
	JWTMode       = "jwt_auth"
)

func main() {
	mode := flag.String("mode", HTTPBasicMode, "Режим работы")

	flag.Parse()

	switch *mode {
	case HTTPBasicMode:
		fmt.Println("HTTP Basic mode") // TODO: to implement
	case CookieMode:
		fmt.Println("Cookie mode") // TODO: to implement
	case JWTMode:
		fmt.Println("JWT Mode") // TODO: to implement
	default:
		fmt.Println("Wrong mode")
		os.Exit(1)
	}
}
