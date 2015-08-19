# etcd-top
Etcd realtime workload analyzer.  Useful for rapid diagnosis of production usage issues and analysis of production request distributions.

The way it determines request sizes is SUPER naive, and this does not make any accuracy guarantees, but it can get you out of an outage by showing you what your cluster is doing.

Optionally, you can export HTTP latency metrics using prometheus by passing in `-prometheus-port=<port>`.
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
1439959542 sniffed 2066 requests over last 1 seconds

Top 3 most popular http requests:
     Sum     Rate Verb Path
     512       37 GET /v2/keys/b
     512       26 GET /v2/keys/z
     507       25 GET /v2/keys/a

Top 3 slowest individual http requests:
     Time Request
176.706371ms PUT /v2/keys/Z
169.777615ms DELETE /v2/keys/D
168.088299ms PUT /v2/keys/x

Top 3 total time spent in requests:
     Time Request
1.174994394s GET /v2/keys/b
1.042694563s GET /v2/keys/Z
1.009130647s GET /v2/keys/P

Top 3 heaviest http requests:
Content-Length Request
      58 PUT /v2/keys/k
      45 PUT /v2/keys/q
      39 PUT /v2/keys/u

Content Length and latency (microseconds) per HTTP verb
       Type     all_sz    all_lat     GET_sz    GET_lat     PUT_sz    PUT_lat  DELETE_sz DELETE_lat    POST_sz   POST_lat
      Count       2066       2062       1340       1340        413        413        222        222         87         87
       50th        104      34622        104      26695        197      52693        178      52169        107      60611
       75th        107      52169        104      38263        197      69720        178      69720        107      74775
       90th        197      70420        104      51649        197      94112        178      89522        110      95058
       99th        197     114949        112      83470        216     146128        187     156724        122     156724
     99.9th        227     168088        147      91330        238     176706        203     169777        122     156724
    99.99th        238     176706        147      92248        238     176706        203     169777        122     156724
        Max        238     176706        147      92248        238     176706        203     169777        122     156724
```
