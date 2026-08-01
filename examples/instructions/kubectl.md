## Connect with kubectl

This tunnel forwards to the Kubernetes API server at `{{.TargetHint}}`. Point
`kubectl` at the local port instead of the real API server address:

```sh
kubectl --server=https://{{.LocalHost}}:{{.LocalPort}} --insecure-skip-tls-verify get nodes
```

**Better:** add a dedicated context instead of passing `--server` every time,
and keep TLS verification instead of skipping it. `--tls-server-name` tells
kubectl which hostname to check the certificate against, since the tunnel's
loopback address is never the name the API server's certificate was issued
for:

```sh
kubectl config set-cluster {{.Name}} \
  --server=https://{{.LocalHost}}:{{.LocalPort}} \
  --certificate-authority=/path/to/cluster-ca.crt \
  --tls-server-name=kubernetes.default.svc
kubectl config set-credentials {{.Name}}-user --token=YOUR_TOKEN
kubectl config set-context {{.Name}} --cluster={{.Name}} --user={{.Name}}-user
kubectl config use-context {{.Name}}
```

Get `cluster-ca.crt` and a token from your cluster administrator, or extract
them from an existing kubeconfig that already works against this cluster.

Both forms need `ntwire connect` running first: `{{.LocalPort}}` is only
valid while the tunnel is up, and may differ from the server's configured
`local_port` if that port was already taken on this machine -- always use the
value shown here.
