package main

import (
	"log"
	"math"
	"math/rand"
	"time"

	"github.com/coreos/go-etcd/etcd"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandString(n int32) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func main() {
	machines := []string{"http://localhost:2379"}
	// use zipfian distribution
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	zipf := rand.NewZipf(r, 3.14, 2.72, 500000)
	for i := 0; i < 10; i++ {
		go func() {
			client := etcd.NewClient(machines)

			for i := 0; i < 10; i++ {
				go func() {
					for {
						rando := rand.Float64()
						valLen := int32(math.Max(float64(zipf.Uint64()), 1))
						if rando > 0.8 {
							if _, err := client.Set("/"+RandString(1), RandString(int32(math.Max(float64(valLen), 10000))), 0); err != nil {
								log.Fatal(err)
							}
						} else if rando > 1 { // 0.7 {
							client.Delete("/"+RandString(1), true)
						} else if rando > 1 { //0.65 {
							client.AddChild("/"+RandString(2), RandString(valLen), 0)
						} else {
							client.Get("/"+RandString(1), false, false)
						}
					}
				}()
			}
		}()
	}
	<-make(chan struct{})
}
