package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-etcd/etcd"
	"github.com/spacejam/loghisto"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func RandString(n int32) string {
	src := rand.NewSource(time.Now().UnixNano())
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

func reporter(metricStream chan *loghisto.ProcessedMetricSet) {
	for m := range metricStream {
		gets := int(m.Metrics["Get_rate"])
		sets := int(m.Metrics["Put_rate"])
		deletes := int(m.Metrics["Delete_rate"])
		addchilds := int(m.Metrics["AddChild_rate"])
		total := gets + sets + deletes + addchilds
		fmt.Printf("total: %10.0d gets: %10.0d sets: %10.0d deletes: %10.0d addchilds: %10.0d\n",
			total, gets, sets, deletes, addchilds)
		fmt.Printf("50th lat GET: %10.0f PUT: %10.0f DELETE: %10.0f POST: %10.0f\n",
			m.Metrics["GetLat_50"]/10e3,
			m.Metrics["PutLat_50"]/10e3,
			m.Metrics["DeleteLat_50"]/10e3,
			m.Metrics["AddChildLat_50"]/10e3,
		)
		fmt.Printf("90th lat GET: %10.0f PUT: %10.0f DELETE: %10.0f POST: %10.0f\n",
			m.Metrics["GetLat_90"]/10e3,
			m.Metrics["PutLat_90"]/10e3,
			m.Metrics["DeleteLat_90"]/10e3,
			m.Metrics["AddChildLat_90"]/10e3,
		)
		fmt.Printf("99.9th lat GET: %10.0f PUT: %10.0f DELETE: %10.0f POST: %10.0f\n",
			m.Metrics["GetLat_99.9"]/10e3,
			m.Metrics["PutLat_99.9"]/10e3,
			m.Metrics["DeleteLat_99.9"]/10e3,
			m.Metrics["AddChildLat_99.9"]/10e3,
		)
		fmt.Printf("99.9th sz GET: %10.0f PUT: %10.0f\n",
			m.Metrics["GetSz_99.9"],
			m.Metrics["PutSz_99.9"],
		)
	}
}
func main() {
	hosts := flag.String("hosts", "http://localhost:2379", "comma separated etcd hosts to spew at")
	flag.Parse()

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)

	ms := loghisto.NewMetricSystem(time.Second, false)
	ms.Start()
	metricStream := make(chan *loghisto.ProcessedMetricSet, 2)
	ms.SubscribeToProcessedMetrics(metricStream)
	defer ms.UnsubscribeFromProcessedMetrics(metricStream)

	machines := strings.Split(*hosts, ",")
	// use zipfian distribution
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	zipf := rand.NewZipf(r, 3.14, 2.72, 500000)
	go reporter(metricStream)
	for i := 0; i < 5; i++ {
		go func() {
			client := etcd.NewClient(machines)

			for i := 0; i < 3; i++ {
				go func() {
					for {
						rando := rand.Float64()
						valLen := int32(math.Max(float64(zipf.Uint64()), 1))
						if rando > 0.8 {
							t := ms.StartTimer("PutLat")
							if _, err := client.Set("/"+RandString(1), RandString(500), 0); err != nil {
								log.Fatal(err)
							}
							t.Stop()
							ms.Histogram("PutSz", float64(valLen))
							ms.Counter("Put", 1)
						} else if rando > 0.7 {
							t := ms.StartTimer("DeleteLat")
							client.Delete("/"+RandString(1), true)
							t.Stop()
							ms.Counter("Delete", 1)
						} else if rando > 0.65 {
							t := ms.StartTimer("AddChildLat")
							client.AddChild("/"+RandString(2), RandString(valLen), 0)
							t.Stop()
							ms.Counter("AddChild", 1)
						} else {
							t := ms.StartTimer("GetLat")
							r, err := client.Get("/"+RandString(1), false, false)
							if err == nil {
								ms.Histogram("GetSz", float64(len(r.Node.Value)))
							}
							t.Stop()
							ms.Counter("Get", 1)
						}
					}
				}()
			}
		}()
	}
	<-make(chan struct{})
}
