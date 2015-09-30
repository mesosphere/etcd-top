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

// This function listens for periodic metrics from the loghisto metric system,
// and upon receipt of a batch of them it will print out the desired topK.
func statPrinter(metricStream chan *loghisto.ProcessedMetricSet, topK, period uint) {
	for m := range metricStream {
		request_counter := float64(0)
		nvs := nameSums{}
		for k, v := range m.Metrics {
			// loghisto adds _rate suffixed metrics for counters and histograms
			if strings.HasSuffix(k, "_rate") && !strings.HasSuffix(k, "_rate_rate") {
				continue
			}
			nvs = append(nvs, nameSum{
				Name: k,
				Sum:  v,
				Rate: m.Metrics[k+"_rate"],
			})
			request_counter += m.Metrics[k+"_rate"]
		}

		fmt.Printf("\n%d sniffed %d requests over last %d seconds\n\n", time.Now().Unix(),
			uint(request_counter), period)
		if len(nvs) == 0 {
			continue
		}
		sort.Sort(nvs)
		fmt.Printf("Top %d most popular http requests:\n", topK)
		fmt.Println("Total Sum  Period Sum Verb Path")
		for _, nv := range nvs[0:int(math.Min(float64(len(nvs)), float64(topK)))] {
			fmt.Printf("%9.1d %7.1d %s\n", int(nv.Sum), int(nv.Rate), nv.Name)
		}
	}
}

// packetDecoder decodes packets and hands them off to the streamRouter
func packetDecoder(packetsIn chan *pcap.Packet, packetsOut chan *pcap.Packet) {
	for pkt := range packetsIn {
		pkt.Decode()
		select {
		case packetsOut <- pkt:
		default:
			fmt.Println("shedding at decoder!")
		}
	}
}

// processor tries to parse an http request or response from each packet,
// and if successful it records metrics about it in the loghisto metric
// system.  On successful parse of a response, it looks up a corresponding
// request so that it can record statistics about http verbs / individual
// paths being hit.
func processor(ms *loghisto.MetricSystem, packetsIn chan *pcap.Packet) {
	for pkt := range packetsIn {
		req, reqErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(pkt.Payload)))
		if reqErr == nil {
			ms.Counter(req.Method+" "+req.URL.Path, 1)
		}
	}
}

// streamRouter takes a decoded packet and routes it to
// a processor that will deal with all requests and responses
// for this particular TCP connection.  This allows the
// processor to own a local map of requests so that it
// can avoid coordinating with other goroutines to perform
// analysis.
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
			select {
			case processors[int(clientPort)%len(processors)] <- pkt:
			default:
				fmt.Println("Shedding load at router!")
			}
		}
	}
}

// 1. parse args
// 2. start the loghisto metric system
// 3. start the processing and printing goroutines
// 4. open the pcap handler
// 5. hand off packets from the handler to the decoder
func main() {
	portsArg := flag.String("ports", "4001,2379", "etcd listening ports")
	iface := flag.String("iface", "eth0", "interface for sniffing traffic on")
	promisc := flag.Bool("promiscuous", true, "promiscuous mode")
	period := flag.Uint("period", 1, "seconds between submissions")
	topK := flag.Uint("topk", 10, "submit stats for the top <K> sniffed paths")
	flag.Parse()

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)

	ms := loghisto.NewMetricSystem(time.Duration(*period)*time.Second, false)
	ms.Start()
	metricStream := make(chan *loghisto.ProcessedMetricSet, 2)
	ms.SubscribeToProcessedMetrics(metricStream)
	defer ms.UnsubscribeFromProcessedMetrics(metricStream)

	go statPrinter(metricStream, *topK, *period)

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

	portArray := strings.Split(*portsArg, ",")
	dst := strings.Join(portArray, " or dst port ")
	src := strings.Join(portArray, " or src port ")
	filter := fmt.Sprintf("tcp and (dst port %s or src port %s)", dst, src)
	fmt.Println("using bpf filter: ", filter)
	if err := h.Setfilter(filter); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	unparsedPackets := make(chan *pcap.Packet, 16384)
	parsedPackets := make(chan *pcap.Packet, 16384)
	for i := 0; i < 5; i++ {
		go packetDecoder(unparsedPackets, parsedPackets)
	}

	processors := []chan *pcap.Packet{}
	for i := 0; i < 50; i++ {
		p := make(chan *pcap.Packet, 16384)
		processors = append(processors, p)
		go processor(ms, p)
	}

	go streamRouter(ports, parsedPackets, processors)

	for {
		pkt := h.Next()
		if pkt != nil {
			select {
			case unparsedPackets <- pkt:
			default:
				fmt.Println("SHEDDING IN MAIN")
			}
		}
	}
}
