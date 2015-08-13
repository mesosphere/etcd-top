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
