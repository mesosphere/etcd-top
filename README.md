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
1439502732
Sum Rate Verb Path
1383 129 GET /v2/members
504 47 GET /v2/keys/dog?quorum=false&recursive=false&sorted=false
437 42 PUT /v2/keys/dog
11 0 PUT /v2/keys/12
11 2 PUT /v2/keys/41
10 1 PUT /v2/keys/56
9 1 PUT /v2/keys/73
9 1 PUT /v2/keys/80
8 1 PUT /v2/keys/70
8 1 PUT /v2/keys/7

1439502733
Sum Rate Verb Path
1513 130 GET /v2/members
550 46 GET /v2/keys/dog?quorum=false&recursive=false&sorted=false
479 42 PUT /v2/keys/dog
14 3 PUT /v2/keys/41
11 0 PUT /v2/keys/12
10 1 PUT /v2/keys/73
10 2 PUT /v2/keys/2
10 0 PUT /v2/keys/56
9 0 PUT /v2/keys/80
9 1 PUT /v2/keys/75

1439502734
Sum Rate Verb Path
1641 128 GET /v2/members
597 47 GET /v2/keys/dog?quorum=false&recursive=false&sorted=false
521 42 PUT /v2/keys/dog
15 1 PUT /v2/keys/41
11 0 PUT /v2/keys/12
11 1 PUT /v2/keys/2
10 1 PUT /v2/keys/80
10 0 PUT /v2/keys/56
10 1 PUT /v2/keys/89
10 3 PUT /v2/keys/60

1439502735
Sum Rate Verb Path
1769 128 GET /v2/members
644 47 GET /v2/keys/dog?quorum=false&recursive=false&sorted=false
562 41 PUT /v2/keys/dog
15 0 PUT /v2/keys/41
11 1 PUT /v2/keys/60
11 0 PUT /v2/keys/12
11 0 PUT /v2/keys/2
11 1 PUT /v2/keys/56
11 1 PUT /v2/keys/80
10 1 PUT /v2/keys/70
```

