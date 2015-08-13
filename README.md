# etcd-top
etcd realtime workload analyzer

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
$ go run etcd-top.go --period=1
1439509750
Top 10 most popular http requests:
     Sum     Rate Verb Path
   64247     2662 PUT /v2/keys/foo
      24        1 GET /v2/members
       2        0 PUT /v2/keys/75
       2        0 PUT /v2/keys/19
       1        0 PUT /v2/keys/58
       1        0 PUT /v2/keys/48
       1        0 PUT /v2/keys/2
       1        0 PUT /v2/keys/13
       1        0 PUT /v2/keys/34
       1        0 PUT /v2/keys/70

Request size stats:
Total bytes transmitted: 4220520
Total requests sniffed:  64295
Content Length Min:      0
Content Length 50th:     65
Content Length 75th:     65
Content Length 90th:     65
Content Length 95th:     65
Content Length 99th:     65
Content Length 99.9th:   65
Content Length 99.99th:  65
Content Length Max:      65

1439509751
Top 10 most popular http requests:
     Sum     Rate Verb Path
   66705     2458 PUT /v2/keys/foo
      25        1 GET /v2/members
       2        0 PUT /v2/keys/19
       2        0 PUT /v2/keys/75
       1        0 PUT /v2/keys/96
       1        1 PUT /v2/keys/20
       1        0 PUT /v2/keys/64
       1        0 PUT /v2/keys/15
       1        0 PUT /v2/keys/50
       1        0 PUT /v2/keys/14

Request size stats:
Total bytes transmitted: 4381992
Total requests sniffed:  66755
Content Length Min:      0
Content Length 50th:     65
Content Length 75th:     65
Content Length 90th:     65
Content Length 95th:     65
Content Length 99th:     65
Content Length 99.9th:   65
Content Length 99.99th:  65
Content Length Max:      65
...
```
