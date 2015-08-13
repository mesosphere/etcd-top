package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akrennmair/gopcap"
	"github.com/spacejam/loghisto"
)

type nameVal struct {
	Name string
	Val  float64
}

type nameVals []nameVal

func (n nameVals) Len() int {
	return len(n)
}
func (n nameVals) Less(i, j int) bool {
	return n[i].Val < n[j].Val
}
func (n nameVals) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func statPrinter(metricStream chan *loghisto.ProcessedMetricSet, topK uint) {
	for m := range metricStream {
		nvs := nameVals{}
		fmt.Printf("\n%d\n", time.Now().Unix())
		for k, v := range m.Metrics {
			nvs = append(nvs, nameVal{
				Name: k,
				Val:  v,
			})
		}
		if len(nvs) == 0 {
			continue
		}
		sort.Sort(nvs)
		for _, nv := range nvs[0:int(math.Min(float64(len(nvs)), float64(topK)))] {
			fmt.Printf("%s: %f\n", nv.Name, nv.Val)
		}
	}
}

func main() {
	portsArg := flag.String("ports", "4001,2379", "etcd listening ports")
	iface := flag.String("iface", "lo", "interface for sniffing traffic on")
	promisc := flag.Bool("promiscuous", false, "whether to perform promiscuous sniffing or not.")
	period := flag.Uint("period", 60, "seconds between submissions")
	topK := flag.Uint("topk", 10, "submit stats for the top <K> sniffed paths")

	flag.Parse()

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)

	ms := loghisto.NewMetricSystem(time.Duration(*period)*time.Second, false)
	ms.Start()
	metricStream := make(chan *loghisto.ProcessedMetricSet, 2)
	ms.SubscribeToProcessedMetrics(metricStream)
	defer ms.UnsubscribeFromProcessedMetrics(metricStream)

	go statPrinter(metricStream, *topK)

	ports := []uint16{}
	for _, p := range strings.Split(*portsArg, ",") {
		p, err := strconv.Atoi(p)
		if err == nil {
			ports = append(ports, uint16(p))
		}
	}

	h, err := pcap.Openlive(*iface, 1518000, *promisc, 100000)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	for {
		for pkt := h.Next(); pkt != nil; pkt = h.Next() {
			pkt.Decode()
			interesting := false
			for _, p := range ports {
				if pkt.TCP != nil && pkt.TCP.DestPort == p {
					interesting = true
				}
			}
			if !interesting {
				continue
			}

			data := string(pkt.Payload)
			if len(data) == 0 {
				continue
			}

			lines := strings.Split(data, "\r\n")
			if len(lines) == 0 {
				continue
			}

			verbReq := strings.Split(lines[0], " ")
			if len(verbReq) < 2 {
				continue
			}
			verb := verbReq[0]
			path := verbReq[1]
			ms.Counter(verb+" "+path, 1)
		}
	}
}
