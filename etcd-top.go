package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	//"io/ioutil"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"../loghisto"
)

type labelPrefix struct {
	label  string
	prefix string
}

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

func statPrinter(metricStream chan *loghisto.ProcessedMetricSet, topK, period uint) {
	for m := range metricStream {
		nvs := nameSums{}
		reqTimes := nameSums{}
		reqSumTimes := nameSums{}
		reqSizes := nameSums{}
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
			if (strings.HasPrefix(k, "globaltimer") ||
				strings.HasPrefix(k, "verbtimer")) &&
				!strings.HasSuffix(k, "_count") {
				// convert to milliseconds
				m.Metrics[k] = v / 1e3
				continue
			}
			if strings.HasPrefix(k, "verbsize ") ||
				strings.HasPrefix(k, "globalsize") ||
				strings.HasPrefix(k, "globaltimer") ||
				strings.HasPrefix(k, "verbtimer") {
				continue
			}

			nvs = append(nvs, nameSum{
				Name: k,
				Sum:  v,
				Rate: m.Metrics[k+"_rate"],
			})
		}

		fmt.Printf("\n%d sniffed %d requests over last %d seconds\n\n", time.Now().Unix(),
			uint64(m.Metrics["globalsize_count"]), period)
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

		labelPrefixes := []labelPrefix{
			{"Content-Length bytes", "globalsize"},
			{"Global Request Timers", "globaltimer"},
		}

		format := "\n%10s "
		for _, verb := range []string{"GET", "PUT", "DELETE", "POST"} {
			labelPrefixes = append(labelPrefixes, labelPrefix{verb + " us", "verbsize " + verb})
			labelPrefixes = append(labelPrefixes, labelPrefix{verb + " us", "verbtimer " + verb})
			format += "%10s "
		}
		format += "\n"
		fmt.Printf("\nContent length (bytes) and latency (microseconds) per HTTP verb\n")
		fmt.Printf("       Type     all_sz    all_lat     GET_sz" +
			"    GET_lat     PUT_sz    PUT_lat  DELETE_sz DELETE_lat" +
			"    POST_sz   POST_lat\n")
		printDistribution(m.Metrics, labelPrefixes...)
	}
}

func printDistribution(metrics map[string]float64, keys ...labelPrefix) {
	tags := []struct {
		label  string
		suffix string
	}{
		{"Count", "_count"},
		{"50th", "_50"},
		{"75th", "_75"},
		{"90th", "_90"},
		{"99th", "_99"},
		{"99.9th", "_99.9"},
		{"99.99th", "_99.99"},
		{"Max", "_max"},
	}
	for _, t := range tags {
		fmt.Printf("%11s", t.label)
		for _, k := range keys {
			fmt.Printf("%11.1d", int(metrics[k.prefix+t.suffix]))
		}
		fmt.Printf("\n")
	}
}

func packetDecoder(packetsIn chan *gopacket.Packet, packetsOut chan *gopacket.Packet) {
	for pkt := range packetsIn {
		pkt.Decode()
		packetsOut <- pkt
	}
}

type HTTPStreamMachine struct {
	seq     uint32
	sofar   *bytes.Buffer
	pending map[uint32]*gopacket.Packet
}

func NewHTTPStreamMachine() HTTPStreamMachine {
	return HTTPStreamMachine{
		seq:     0,
		sofar:   bytes.NewBuffer([]byte{}),
		pending: map[uint32]*gopacket.Packet{},
	}
}

func (sm HTTPStreamMachine) Feed(pkt *gopacket.Packet) error {
	if pkt.TCP != nil {
		// This is the initial packet
		if 0 != (pkt.TCP.Flags & pcap.TCP_SYN) {
			sm.seq = pkt.TCP.Seq
		}
		/*
			fmt.Println(pkt.TCP.FlagsString())
			fmt.Println(pkt.TCP.SrcPort, pkt.TCP.DestPort, pkt.TCP.Seq, pkt.TCP.Ack)
			fmt.Println(string(pkt.Payload))
			fmt.Println()
			if pkt.TCP.Seq == sm.seq+1 {
				sm.sofar.Write(pkt.Payload)
				sm.AssembleOld()
			}
		*/
	}
	return nil
}

func (sm HTTPStreamMachine) AssembleOld() {}

func (sm HTTPStreamMachine) Ready() bool { return false }

func (sm HTTPStreamMachine) Get() []byte {
	return sm.sofar.Bytes()
}

func processor(ms *loghisto.MetricSystem, packetsIn chan *gopacket.Packet, ports []uint16) {
	streamMachine := NewHTTPStreamMachine()
	reqTimers := map[uint32]loghisto.TimerToken{}
	reqVerbTimers := map[uint32]loghisto.TimerToken{}
	globalTimers := map[uint32]loghisto.TimerToken{}
	reqVerb := map[uint32]string{}

	for pkt := range packetsIn {
		var token uint32
		for _, p := range ports {
			if pkt.TCP == nil {
				break
			}
			if pkt.TCP.SrcPort == p {
				token = (uint32(pkt.TCP.SrcPort) << 8) + uint32(pkt.TCP.DestPort)
				break
			}
			if pkt.TCP.DestPort == p {
				token = (uint32(pkt.TCP.DestPort) << 8) + uint32(pkt.TCP.SrcPort)
				break
			}
		}
		//streamToken := (uint32(pkt.TCP.SrcPort) << 8) + uint32(pkt.TCP.DestPort)
		streamMachine.Feed(pkt)
		//fmt.Println(string(pkt.Payload))
		req, reqErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(pkt.Payload)))
		if reqErr == nil {
			reqTimers[token] = ms.StartTimer("timer " + req.Method + " " + req.URL.Path)
			reqVerbTimers[token] = ms.StartTimer("verbtimer " + req.Method)
			globalTimers[token] = ms.StartTimer("globaltimer")
			ms.Histogram("size "+req.Method+" "+req.URL.Path, float64(req.ContentLength))
			ms.Counter(req.Method+" "+req.URL.Path, 1)
			reqVerb[token] = req.Method
			if req.Method == "PUT" || req.Method == "POST" {
				ms.Histogram("globalsize", float64(req.ContentLength))
				ms.Histogram("verbsize "+req.Method, float64(req.ContentLength))
			}
		} else {
			res, resErr := http.ReadResponse(bufio.NewReader(bytes.NewReader(pkt.Payload)), nil)
			if resErr != nil {
				// not a valid request or response
				continue
			}
			reqTimer, present := reqTimers[token]
			if present {
				reqTimer.Stop()
				delete(reqTimers, token)
			}

			verb, present := reqVerb[token]
			if present {
				if !(verb == "PUT" || verb == "POST") {
					/*
						fmt.Println(verb, res.ContentLength)
						body, err := ioutil.ReadAll(res.Body)
						if err == nil {
							fmt.Println(len(body))
						}
						res.Body.Close()
					*/
					ms.Histogram("globalsize", float64(res.ContentLength))
					ms.Histogram("verbsize "+verb, float64(res.ContentLength))
				}
				delete(reqVerb, token)
			}

			verbTimer, present := reqVerbTimers[token]
			if present {
				verbTimer.Stop()
				delete(reqVerbTimers, token)
			}
			globalTimer, present := globalTimers[token]
			if present {
				globalTimer.Stop()
				delete(globalTimers, token)
			}
		}
	}
}

func streamRouter(
	ports []uint16,
	parsedPackets chan *gopacket.Packet,
	processors []chan *gopacket.Packet,
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
	portsArg := flag.String("ports", "4001,2379,7001", "etcd listening ports")
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

	unparsedPackets := make(chan *gopacket.Packet)
	parsedPackets := make(chan *gopacket.Packet)
	for i := 0; i < 5; i++ {
		go packetDecoder(unparsedPackets, parsedPackets)
	}

	processors := []chan *gopacket.Packet{}
	for i := 0; i < 1; i++ {
		p := make(chan *gopacket.Packet)
		processors = append(processors, p)
		go processor(ms, p, ports)
	}

	go streamRouter(ports, parsedPackets, processors)

	for {
		pkt := h.ReadPacketData()
		if pkt != nil {
			unparsedPackets <- pkt
		}
	}
}
