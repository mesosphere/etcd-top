package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akrennmair/gopcap"
	"github.com/spacejam/loghisto"
)

type nameSum struct {
	Name string
	Sum  float64
	Rate float64
}

type nameSums []nameSum

func (n nameSums) Len() int {
	return len(n)
}
func (n nameSums) Less(i, j int) bool {
	return n[i].Sum > n[j].Sum
}
func (n nameSums) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func statPrinter(metricStream chan *loghisto.ProcessedMetricSet, topK uint) {
	for m := range metricStream {
		cls := map[string]uint64{}
		nvs := nameSums{}
		fmt.Printf("\n%d\n", time.Now().Unix())
		for k, v := range m.Metrics {
			if strings.HasSuffix(k, "_rate") {
				continue
			}
			if strings.HasPrefix(k, "ContentLength") {
				cls[k] = uint64(v)
				continue
			}
			nvs = append(nvs, nameSum{
				Name: k,
				Sum:  v,
				Rate: m.Metrics[k+"_rate"],
			})
		}
		if len(nvs) == 0 {
			continue
		}
		sort.Sort(nvs)
		fmt.Printf("Top %d most popular http requests:\n", topK)
		fmt.Println("     Sum     Rate Verb Path")
		for _, nv := range nvs[0:int(math.Min(float64(len(nvs)), float64(topK)))] {
			fmt.Printf("%8.1d %8.1d %s\n", int(nv.Sum), int(nv.Rate), nv.Name)
		}
		fmt.Printf("\nRequest size stats:\n")
		fmt.Println("Total requests sniffed: ", cls["ContentLength_agg_count"])
		fmt.Println("Content Length Min:     ", cls["ContentLength_min"])
		fmt.Println("Content Length 50th:    ", cls["ContentLength_50"])
		fmt.Println("Content Length 75th:    ", cls["ContentLength_75"])
		fmt.Println("Content Length 90th:    ", cls["ContentLength_90"])
		fmt.Println("Content Length 95th:    ", cls["ContentLength_95"])
		fmt.Println("Content Length 99th:    ", cls["ContentLength_99"])
		fmt.Println("Content Length 99.9th:  ", cls["ContentLength_99.9"])
		fmt.Println("Content Length 99.99th: ", cls["ContentLength_99.99"])
		fmt.Println("Content Length Max:     ", cls["ContentLength_max"])
	}
}

func packetDecoder(packetsIn chan *pcap.Packet, packetsOut chan *pcap.Packet) {
	for pkt := range packetsIn {
		pkt.Decode()
		packetsOut <- pkt
	}
}

func processor(ms *loghisto.MetricSystem, packetsIn chan *pcap.Packet) {
	for pkt := range packetsIn {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(pkt.Payload)))
		if err != nil {
			continue
		}
		ms.Histogram("ContentLength", float64(req.ContentLength))
		ms.Counter(req.Method+" "+req.URL.Path, 1)
	}
}

func streamRouter(ports []uint16, parsedPackets chan *pcap.Packet, processors []chan *pcap.Packet) {
	for pkt := range parsedPackets {
		clientPort := uint16(0)
		for _, p := range ports {
			if pkt.TCP == nil {
				break
			}
			if pkt.TCP.SrcPort == p {
				clientPort = pkt.TCP.DestPort
				break
			}
			if pkt.TCP.DestPort == p {
				clientPort = pkt.TCP.SrcPort
				break
			}
		}
		if clientPort != 0 {
			// client Port can be assumed to have sufficient entropy for
			// distribution among processors, and we want the same
			// tcp stream to go to the same processor every time
			// so that if we do proper packet reconstruction it will
			// be easier.
			processors[int(clientPort)%len(processors)] <- pkt
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

	h, err := pcap.Openlive(*iface, 1518, *promisc, 1000)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer h.Close()

	unparsedPackets := make(chan *pcap.Packet)
	parsedPackets := make(chan *pcap.Packet)
	for i := 0; i < 5; i++ {
		go packetDecoder(unparsedPackets, parsedPackets)
	}

	processors := []chan *pcap.Packet{}
	for i := 0; i < 5; i++ {
		p := make(chan *pcap.Packet)
		processors = append(processors, p)
		go processor(ms, p)
	}

	go streamRouter(ports, parsedPackets, processors)

	for {
		for pkt := h.Next(); pkt != nil; pkt = h.Next() {
			unparsedPackets <- pkt
		}
	}
}
