package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"sort"
	//"io/ioutil"

	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

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

type resToken struct {
	res   *http.Response
	token uint32
}
type reqToken struct {
	req   *http.Request
	token uint32
}

func processor(ms *loghisto.MetricSystem, packetsIn chan gopacket.Packet, ports []uint16) {
	reqTimers := map[uint32]loghisto.TimerToken{}
	reqVerbTimers := map[uint32]loghisto.TimerToken{}
	globalTimers := map[uint32]loghisto.TimerToken{}
	reqVerb := map[uint32]string{}
	processedRequests := make(chan reqToken, 100)
	processedResponses := make(chan resToken, 100)

	streamFactory := &httpStreamFactory{
		processedRequests:  processedRequests,
		processedResponses: processedResponses,
		ports:              ports,
	}

	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	ticker := time.Tick(time.Millisecond)

	for {
		select {
		case pkt := <-packetsIn:
			tcp := pkt.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(pkt.NetworkLayer().NetworkFlow(), tcp, pkt.Metadata().Timestamp)
		case reqToken := <-processedRequests:
			req := reqToken.req
			token := reqToken.token
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
		//bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
		//log.Println("Received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body")
		case resToken := <-processedResponses:
			res := resToken.res
			token := resToken.token
			reqTimer, present := reqTimers[token]
			if present {
				reqTimer.Stop()
				delete(reqTimers, token)
			}

			verb, present := reqVerb[token]
			if present {
				if !(verb == "PUT" || verb == "POST") {
					//	fmt.Println(verb, res.ContentLength)
					//	body, err := ioutil.ReadAll(res.Body)
					//	if err == nil {
					//		fmt.Println(len(body))
					//	}
					//	res.Body.Close()
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

			//bodyBytes := tcpreader.DiscardBytesToEOF(res.Body)
			//log.Println("Received response from stream", h.net, h.transport, ":", res, "with", bodyBytes, "bytes in request body")
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Millisecond * -2))
		}
	}
}

func streamRouter(
	ports []uint16,
	parsedPackets chan gopacket.Packet,
	processors []chan gopacket.Packet,
) {
	for pkt := range parsedPackets {
		tcp := pkt.TransportLayer().(*layers.TCP)
		clientPort := uint16(0)
		for _, p := range ports {
			if uint16(tcp.SrcPort) == p {
				clientPort = uint16(tcp.DstPort)
				break
			}
			if uint16(tcp.DstPort) == p {
				clientPort = uint16(tcp.SrcPort)
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

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	processedRequests  chan reqToken
	processedResponses chan resToken
	ports              []uint16
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport     gopacket.Flow
	r                  tcpreader.ReaderStream
	processedRequests  chan reqToken
	processedResponses chan resToken
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:                net,
		transport:          transport,
		r:                  tcpreader.NewReaderStream(),
		processedRequests:  h.processedRequests,
		processedResponses: h.processedResponses,
	}

	srcStr, dstStr := transport.Endpoints()
	src, err := strconv.Atoi(srcStr.String())
	if err != nil {
		log.Println("error converting endpoint")
	}
	dst, err := strconv.Atoi(dstStr.String())
	if err != nil {
		log.Println("error converting endpoint")
	}

	for _, p := range h.ports {
		if src == int(p) {
			go hstream.readRes()
			break
		}
		if dst == int(p) {
			go hstream.readReq()
			break
		}
	}

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) readReq() {
	reqbuf := bufio.NewReader(&h.r)
	done := false
	for {
		req, reqErr := http.ReadRequest(reqbuf)
		if reqErr == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if done {
			continue
		} else if reqErr != nil {
		} else {
			srcStr, dstStr := h.transport.Endpoints()
			src, err := strconv.Atoi(srcStr.String())
			if err != nil {
				log.Println("error converting endpoint")
			}
			dst, err := strconv.Atoi(dstStr.String())
			if err != nil {
				log.Println("error converting endpoint")
			}
			token := (uint32(dst) << 8) + uint32(src)
			h.processedRequests <- reqToken{
				req:   req,
				token: token,
			}
			done = true
		}
	}
}

func (h *httpStream) readRes() {
	resbuf := bufio.NewReader(&h.r)
	done := false
	for {
		res, resErr := http.ReadResponse(resbuf, nil)
		if resErr == io.EOF {
			return
		} else if resErr != nil {
			continue
		} else if done {
			continue
		} else {
			if res != nil && res.Body != nil {
				srcStr, dstStr := h.transport.Endpoints()
				src, err := strconv.Atoi(srcStr.String())
				if err != nil {
					log.Println("error converting endpoint")
				}
				dst, err := strconv.Atoi(dstStr.String())
				if err != nil {
					log.Println("error converting endpoint")
				}
				token := (uint32(src) << 8) + uint32(dst)
				h.processedResponses <- resToken{
					res:   res,
					token: token,
				}
				done = true
			} else {
				log.Println("nil res Body")
			}
		}
	}
}
func main() {
	portsArg := flag.String("ports", "2379,4001", "etcd listening ports")
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

	parsedPackets := make(chan gopacket.Packet)

	processors := []chan gopacket.Packet{}
	for i := 0; i < 10; i++ {
		p := make(chan gopacket.Packet)
		processors = append(processors, p)
		go processor(ms, p, ports)
	}

	go streamRouter(ports, parsedPackets, processors)

	defer util.Run()()

	handle, err := pcap.OpenLive(*iface, 1518, *promisc, 1)
	if err != nil {
		log.Fatal(err)
	}

	portArray := strings.Split(*portsArg, ",")
	dst := strings.Join(portArray, " or dst port ")
	src := strings.Join(portArray, " or src port ")
	filter := fmt.Sprintf("tcp and (dst port %s or src port %s)", dst, src)
	fmt.Println("using bpf filter: ", filter)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			//log.Println(packet)
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			parsedPackets <- packet
		}
	}
}
