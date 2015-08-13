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

1439427855
GET /v2/members: 1141.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 869.000000
PUT /v2/keys/dog: 273.000000
GET /v2/members_rate: 120.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false_rate: 65.000000
PUT /v2/keys/dog_rate: 55.000000

1439427856
GET /v2/members: 1233.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 918.000000
PUT /v2/keys/dog: 315.000000
GET /v2/members_rate: 92.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false_rate: 49.000000
PUT /v2/keys/dog_rate: 42.000000

1439427857
GET /v2/members: 1323.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 967.000000
PUT /v2/keys/dog: 357.000000
GET /v2/members_rate: 90.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false_rate: 49.000000
PUT /v2/keys/dog_rate: 42.000000

1439427858
GET /v2/members: 1414.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false: 1016.000000
PUT /v2/keys/dog: 398.000000
GET /v2/members_rate: 91.000000
GET /v2/keys/dog?quorum=false&recursive=false&sorted=false_rate: 49.000000
PUT /v2/keys/dog_rate: 41.000000
```
