# etcd-top
Etcd realtime workload analyzer.  Useful for rapid diagnosis of production usage issues and analysis of production request distributions.

The way it determines request sizes and latency is SUPER naive, and this does not make any accuracy guarantees, but it can get you out of an outage by showing you what your cluster is doing.

Latency measurements are heavily colored by skew in the collection system itself, and they are likely to be pretty off.

Request counts are fairly accurate, but still slightly lossy.

Optionally, you can export HTTP latency metrics using prometheus by passing in `-prometheus-port=<port>`.  This is not for long-term metric collection, and will die due to a memory leaks eventually.

usage:
```
  -iface="eth0": interface for sniffing traffic on
  -period=60: seconds between submissions
  -ports="4001,2379": etcd listening ports
  -prometheus-port=0: port for prometheus exporter to listen on
  -promiscuous=false: whether to perform promiscuous sniffing or not.
  -topk=10: submit stats for the top <K> sniffed paths
```

result:
```
go run etcd-top.go --period=1 -topk=3 -prometheus-port=9092
1440035702 sniffed 1074 requests over last 1 seconds

Top 3 most popular http requests:
     Sum     Rate Verb Path
    1305       22 GET /v2/keys/c
    1302        8 GET /v2/keys/S
    1297       10 GET /v2/keys/h

Top 3 slowest individual http requests:
     Time Request
112.672956ms GET /v2/keys/k
106.111394ms PUT /v2/keys/q
87.749786ms GET /v2/keys/d

Top 3 total time spent in requests:
     Time Request
164.135442ms GET /v2/keys/d
113.830209ms GET /v2/keys/k
106.485819ms PUT /v2/keys/q

Top 3 heaviest http requests:
Content-Length Request
     506 PUT /v2/keys/p
     506 PUT /v2/keys/s
     506 PUT /v2/keys/b

Content Length and latency (microseconds) per HTTP verb
       Type     all_sz    all_lat     GET_sz    GET_lat     PUT_sz    PUT_lat  DELETE_sz DELETE_lat    POST_sz   POST_lat
      Count       1074       1023        663        663        187        187        120        120         53         53
       50th        594        111        594        101       1175        110        670        105        107        117
       75th        594        156        594        138       1175        154        670        142        108        187
       90th       1175        465        594        348       1175       1143        670        235        113        337
```
