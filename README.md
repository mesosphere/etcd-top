# etcd-top
Etcd realtime workload analyzer.  Useful for rapid diagnosis of production usage issues and analysis of production request distributions.

usage:
```
  -iface="lo": interface for sniffing traffic on
  -period=60: seconds between submissions
  -ports="4001,2379": etcd listening ports
  -promiscuous=false: whether to perform promiscuous sniffing or not.
  -topk=10: submit stats for the top <K> sniffed paths
```

result:
```
$ go run etcd-top.go --period=1 -iface=eth0 -topk=3
1439515150
Top 3 most popular http requests:
     Sum     Rate Verb Path
    6067      251 PUT /v2/keys/foo
     406       14 GET /v2/members
       8        2 PUT /v2/keys/5

Top 3 slowest individual http requests:
     Time Request
54.29811ms PUT /v2/keys/31
49.624736ms PUT /v2/keys/75
49.130961ms PUT /v2/keys/foo

Top 3 total time spent in requests:
     Time Request
6.262377577s PUT /v2/keys/foo
279.094478ms GET /v2/members
67.231305ms PUT /v2/keys/5

Top 3 heaviest http requests:
Content-Length Request
   59873 PUT /v2/keys/foo
      15 PUT /v2/keys/3
      15 PUT /v2/keys/2

Overall request size stats:
Total requests sniffed:  13770
Content Length Min:      0
Content Length 50th:     180
Content Length 75th:     59873
Content Length 90th:     59873
Content Length 95th:     59873
Content Length 99th:     59873
Content Length 99.9th:   59873
Content Length 99.99th:  59873
Content Length Max:      59873

1439515151
Top 3 most popular http requests:
     Sum     Rate Verb Path
    6310      243 PUT /v2/keys/foo
     422       16 GET /v2/members
       8        0 PUT /v2/keys/21

Top 3 slowest individual http requests:
     Time Request
60.008692ms PUT /v2/keys/foo
31.642128ms PUT /v2/keys/58
31.327283ms PUT /v2/keys/2

Top 3 total time spent in requests:
     Time Request
5.766000298s PUT /v2/keys/foo
207.272109ms GET /v2/members
31.642128ms PUT /v2/keys/58

Top 3 heaviest http requests:
Content-Length Request
   59873 PUT /v2/keys/foo
      15 PUT /v2/keys/13
      15 PUT /v2/keys/30

Overall request size stats:
Total requests sniffed:  14320
Content Length Min:      0
Content Length 50th:     15
Content Length 75th:     59873
Content Length 90th:     59873
Content Length 95th:     59873
Content Length 99th:     59873
Content Length 99.9th:   59873
Content Length 99.99th:  59873
Content Length Max:      59873
```
