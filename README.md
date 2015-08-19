# etcd-top
Etcd realtime workload analyzer.  Useful for rapid diagnosis of production usage issues and analysis of production request distributions.

The way it determines request sizes is SUPER naive, and this does not make any accuracy guarantees, but it can get you out of an outage by showing you what your cluster is doing.

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
1439955626 sniffed 2331 requests over last 1 seconds

Top 3 most popular http requests:
     Sum     Rate Verb Path
     131       41 GET /v2/keys/L
     123       31 GET /v2/keys/u
     121       38 GET /v2/keys/A

Top 3 slowest individual http requests:
     Time Request
285.570644ms PUT /v2/keys/p
285.570644ms PUT /v2/keys/Y
285.570644ms PUT /v2/keys/C

Top 3 total time spent in requests:
     Time Request
1.50260116s GET /v2/keys/r
1.331866909s GET /v2/keys/w
1.207473801s GET /v2/keys/L

Top 3 heaviest http requests:
Content-Length Request
      32 POST /v2/keys/uk
      26 PUT /v2/keys/h
      26 PUT /v2/keys/y

Content Length and latency (microseconds) per HTTP verb
       Type     all_sz    all_lat     GET_sz    GET_lat     PUT_sz    PUT_lat  DELETE_sz DELETE_lat    POST_sz   POST_lat
      Count       2331       2323       1523       1523        470        470        222        222        108        108
       50th        104   30706962        104   24642914        197   40629297        178   42287410        107   45353593
       75th        107   43575253        104   36397111        197   52169050        178   52169050        107   61836229
       90th        197   63085403        104   49624736        197   69026426        178   67659611        111  101950707
       99th        197  193347567        104   96013560        199  282729168        178  277130756        119  277130756
     99.9th        201  285570644        114  195290742        207  285570644        189  285570644        133  279915966
    99.99th        207  285570644        114  195290742        207  285570644        189  285570644        133  279915966
        Max        207  285570644        114  195290742        207  285570644        189  285570644        133  279915966
```
