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

1439427981
GET /v2/members: 121.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 65.000000
PUT /v2/keys/dog: 56.000000

1439427982
GET /v2/members: 211.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 112.000000
PUT /v2/keys/dog: 99.000000

1439427983
GET /v2/members: 302.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 160.000000
PUT /v2/keys/dog: 142.000000

1439427984
GET /v2/members: 393.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 209.000000
PUT /v2/keys/dog: 184.000000

1439427985
GET /v2/members: 484.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 257.000000
PUT /v2/keys/dog: 226.000000

1439427986
GET /v2/members: 574.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 305.000000
PUT /v2/keys/dog: 269.000000
```
