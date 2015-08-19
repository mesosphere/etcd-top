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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spacejam/loghisto"
)

var (
	promGauges = map[string]prometheus.Gauge{}
)

func init() {
	verbs := []string{"GET", "PUT", "DELETE", "POST"}
	promSuffixes := []string{"_50", "_75", "_90", "_99", "_max", "_count"}
	for _, v := range verbs {
		for _, s := range promSuffixes {
			metric := "etcdtop_" + v + s
			gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: metric, Help: metric + " latency in microseconds"})
			prometheus.MustRegister(gauge)
			promGauges[metric] = gauge
		}
	}
}

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
		metrics := map[string]uint64{}
		nvs := nameSums{}
		reqTimes := nameSums{}
		reqSumTimes := nameSums{}
		reqSizes := nameSums{}
		for k, v := range m.Metrics {
			if strings.HasPrefix(k, "verbtimer ") &&
				!strings.HasSuffix(k, "_count") {
				// convert to milliseconds
				m.Metrics[k] = v / 1e3
				continue
			}
			if strings.HasPrefix(k, "globaltimer") &&
				!strings.HasSuffix(k, "_count") {
				// convert to milliseconds
				m.Metrics[k] = v / 1e3
				continue
			}

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
			if strings.HasPrefix(k, "globalsize") {
				metrics[k] = uint64(v)
				continue
			}
			if strings.HasPrefix(k, "verbsize ") ||
				strings.HasPrefix(k, "verbtimer") ||
				strings.HasPrefix(k, "globaltimer") {
				continue
			}

			nvs = append(nvs, nameSum{
				Name: k,
				Sum:  v,
				Rate: m.Metrics[k+"_rate"],
			})
		}

		fmt.Printf("\n%d sniffed %d requests over last %d seconds\n\n", time.Now().Unix(),
			metrics["globalsize_count"], period)
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
		fmt.Printf("\nContent Length and latency (microseconds) per HTTP verb\n")
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
			splits := strings.Split(k.prefix+t.suffix, " ")
			if len(splits) != 2 {
				continue
			}
			promSuffix := splits[1]
			g, present := promGauges["etcdtop_"+promSuffix]
			if present {
				g.Set(metrics[k.prefix+t.suffix])
			}
		}
		fmt.Printf("\n")
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
	reqVerbTimers := map[uint32]loghisto.TimerToken{}
	globalTimers := map[uint32]loghisto.TimerToken{}
	reqVerb := map[uint32]string{}

	for pkt := range packetsIn {
		var token uint32
		req, reqErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(pkt.Payload)))
		if reqErr == nil {
			token = (uint32(pkt.TCP.SrcPort) << 8) + uint32(pkt.TCP.DestPort)
			reqTimers[token] = ms.StartTimer("timer " + req.Method + " " + req.URL.Path)
			reqVerbTimers[token] = ms.StartTimer("verbtimer " + req.Method)
			globalTimers[token] = ms.StartTimer("globaltimer")
			ms.Histogram("size "+req.Method+" "+req.URL.Path, float64(req.ContentLength))
			ms.Counter(req.Method+" "+req.URL.Path, 1)
			reqVerb[token] = req.Method
		} else {
			res, resErr := http.ReadResponse(bufio.NewReader(bytes.NewReader(pkt.Payload)), nil)
			if resErr != nil {
				// not a valid request or response
				continue
			}
			ms.Histogram("globalsize", float64(res.ContentLength))
			token = (uint32(pkt.TCP.DestPort) << 8) + uint32(pkt.TCP.SrcPort)
			reqTimer, present := reqTimers[token]
			if present {
				reqTimer.Stop()
				delete(reqTimers, token)
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
			verb, present := reqVerb[token]
			if present {
				ms.Histogram("verbsize "+verb, float64(res.ContentLength))
				delete(reqVerb, token)
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
	prometheusPort := flag.Uint("prometheus-port", 0, "port for prometheus exporter to listen on")
	flag.Parse()

	if *prometheusPort != 0 {
		http.Handle("/metrics", prometheus.UninstrumentedHandler())
		go http.ListenAndServe(":"+strconv.Itoa(int(*prometheusPort)), nil)
	}

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
