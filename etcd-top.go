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
		reqTimes := nameSums{}
		reqSumTimes := nameSums{}
		reqSizes := nameSums{}
		fmt.Printf("\n%d\n", time.Now().Unix())
		for k, v := range m.Metrics {
			if strings.HasSuffix(k, "_rate") {
				continue
			}
			if strings.HasPrefix(k, "timer ") {
				if strings.HasSuffix(k, "_max") {
					reqTimes = append(reqTimes, nameSum{
						Name: strings.TrimSuffix(strings.TrimPrefix(k, "timer "), "_max"),
						Sum:  v,
					})
				}
				if strings.HasSuffix(k, "_sum") && !strings.HasSuffix(k, "_agg_sum") {
					reqSumTimes = append(reqSumTimes, nameSum{
						Name: strings.TrimSuffix(strings.TrimPrefix(k, "timer "), "_sum"),
						Sum:  v,
					})
				}
				continue
			}
			if strings.HasPrefix(k, "size ") {
				if strings.HasSuffix(k, "_max") {
					reqSizes = append(reqSizes, nameSum{
						Name: strings.TrimSuffix(strings.TrimPrefix(k, "size "), "_max"),
						Sum:  v,
					})
				}
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
		sort.Sort(reqTimes)
		fmt.Printf("\nTop %d slowest individual http requests:\n", topK)
		fmt.Println("     Time Request")
		for _, nv := range reqTimes[0:int(math.Min(float64(len(reqTimes)), float64(topK)))] {
			fmt.Printf("%10s %s\n", time.Duration(nv.Sum).String(), nv.Name)
		}

		sort.Sort(reqSumTimes)
		fmt.Printf("\nTop %d total time spent in requests:\n", topK)
		fmt.Println("     Time Request")
		for _, nv := range reqSumTimes[0:int(math.Min(float64(len(reqSumTimes)), float64(topK)))] {
			fmt.Printf("%10s %s\n", time.Duration(nv.Sum).String(), nv.Name)
		}

		sort.Sort(reqSizes)
		fmt.Printf("\nTop %d heaviest http requests:\n", topK)
		fmt.Println("Content-Length Request")
		for _, nv := range reqSizes[0:int(math.Min(float64(len(reqSizes)), float64(topK)))] {
			fmt.Printf("%8.1d %s\n", int(nv.Sum), nv.Name)
		}
		fmt.Printf("\nOverall request size stats:\n")
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
	reqTimers := map[uint32]loghisto.TimerToken{}
	processRequest := func(req *http.Request) {

	}

	processResponse := func(res *http.Response) {

	}

	for pkt := range packetsIn {
		var token uint32
		req, reqErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(pkt.Payload)))
		if reqErr == nil {
			processRequest(req)
			token = (uint32(pkt.TCP.SrcPort) << 8) + uint32(pkt.TCP.DestPort)
			reqTimers[token] = ms.StartTimer("timer " + req.Method + " " + req.URL.Path)
			ms.Histogram("size "+req.Method+" "+req.URL.Path, float64(req.ContentLength))
			ms.Histogram("ContentLength", float64(req.ContentLength))
			ms.Counter(req.Method+" "+req.URL.Path, 1)
		} else {
			res, resErr := http.ReadResponse(bufio.NewReader(bytes.NewReader(pkt.Payload)), nil)
			if resErr != nil {
				// not a valid request or response
				continue
			}
			processResponse(res)
			ms.Histogram("ContentLength", float64(res.ContentLength))
			token = (uint32(pkt.TCP.DestPort) << 8) + uint32(pkt.TCP.SrcPort)
			timer, present := reqTimers[token]
			if present {
				timer.Stop()
			}
		}
	}
}

func streamRouter(
	ports []uint16,
	parsedPackets chan *pcap.Packet,
	processors []chan *pcap.Packet,
) {
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
	iface := flag.String("iface", "eth0", "interface for sniffing traffic on")
	promisc := flag.Bool("promiscuous", false, "promiscuous mode")
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
		pkt := h.Next()
		if pkt != nil {
			unparsedPackets <- pkt
		}
	}
}
