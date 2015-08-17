# etcd-top
Etcd realtime workload analyzer.  Useful for rapid diagnosis of production usage issues and analysis of production request distributions.

usage:
```
  -iface="eth0": interface for sniffing traffic on
  -period=60: seconds between submissions
  -ports="4001,2379": etcd listening ports
  -promiscuous=false: whether to perform promiscuous sniffing or not.
  -topk=10: submit stats for the top <K> sniffed paths
```

result:
```
$ go run etcd-top.go --period=1 -iface=eth0 -topk=3
1439855242 sniffed 1719 requests over last 1 seconds

Top 3 most popular http requests:
     Sum     Rate Verb Path
     300       27 GET /v2/keys/a
     294       34 GET /v2/keys/A
     291       27 GET /v2/keys/I

Top 3 slowest individual http requests:
     Time Request
168.088299ms GET /v2/keys/q
166.415793ms GET /v2/keys/O
140.399149ms PUT /v2/keys/C

Top 3 total time spent in requests:
     Time Request
1.457908592s GET /v2/keys/o
1.419160568s GET /v2/keys/O
1.295238146s GET /v2/keys/M

Top 3 heaviest http requests:
Content-Length Request
     105 PUT /v2/keys/H
     105 PUT /v2/keys/T
     105 PUT /v2/keys/m

Content Length and latency (microseconds) per HTTP verb
       Type     all_sz    all_lat     GET_sz    GET_lat     PUT_sz    PUT_lat  DELETE_sz DELETE_lat    POST_sz   POST_lat
      Count       1719       1487       1193       1193        294        294          0          0          0          0
       50th        195   34277508        195   32281341        375   55951733          0          0          0          0
       75th        195   57082033        195   50123473        375   72565487          0          0          0          0
       90th        375   77827078        195   73294782        375   98937608          0          0          0          0
       99th        375  132222939        375  132222939        375  130907299          0          0          0          0
     99.9th        375  166415793        375  166415793        375  140399149          0          0          0          0
    99.99th        375  168088299        375  168088299        375  140399149          0          0          0          0
        Max        375  168088299        375  168088299        375  140399149          0          0          0          0
```
