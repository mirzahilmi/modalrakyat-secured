package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {
	args := os.Args[1:]
	key, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		log.Fatalln(err)
	}
	digest := md5.Sum(key)
	digestEnc := base64.StdEncoding.EncodeToString(digest[:])
	fmt.Println(digestEnc)
}
