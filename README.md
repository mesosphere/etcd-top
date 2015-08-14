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
1439589180 sniffed 71133 requests in 15 seconds
Top 3 most popular http requests:
     Sum     Rate Verb Path
     732      732 PUT /v2/keys/e
     726      726 PUT /v2/keys/g
     725      725 PUT /v2/keys/J

Top 3 slowest individual http requests:
     Time Request
71.128594ms PUT /v2/keys/M
70.420853ms PUT /v2/keys/C
70.420853ms PUT /v2/keys/w

Top 3 total time spent in requests:
     Time Request
14.136272732s PUT /v2/keys/e
14.046793453s PUT /v2/keys/m
13.980721012s PUT /v2/keys/f

Top 3 heaviest http requests:
Content-Length Request
     236 PUT /v2/keys/u
     203 PUT /v2/keys/t
     147 PUT /v2/keys/T

Content-Length distribution in bytes:
Min:      0
50th:     115
75th:     178
90th:     182
95th:     185
99th:     195
99.9th:   236
99.99th:  303
Max:      410

GET distribution in microseconds:
Min:      3506
50th:     3506
75th:     3506
90th:     3506
95th:     3506
99th:     3506
99.9th:   3506
99.99th:  3506
Max:      3506

PUT distribution in microseconds:
Min:      13
50th:     17021
75th:     29799
90th:     37132
95th:     40629
99th:     52693
99.9th:   63085
99.99th:  70420
Max:      71128
```
