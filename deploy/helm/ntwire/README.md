# ntwire Helm chart

This chart deploys one `ntwire-server`, `ntwire-relay`, or persistent
`ntwire connect` client. Set `component` to select it. The matching
`server.config`, `relay.config`, or `client.config` map is rendered directly
as that component's YAML configuration file; it is not a chart-specific
abstraction over ntwire configuration.

```sh
helm repo add ntwire https://ntwire.io/charts
helm repo update
helm upgrade --install ntwire-server ntwire/ntwire \
  --namespace ntwire --create-namespace \
  --values my-server-values.yaml
```

This installs the newest published chart. Add `--version <chart-version>` to
pin an upgrade, for example during a controlled rollout. The source-tree chart
remains available at `deploy/helm/ntwire` for development and unreleased
changes.

Start from `values.yaml`, set `component`, then change only the selected
configuration map. Use a separate values file rather than `--set` for
configuration: it preserves YAML lists and avoids placing sensitive values in
the shell history.

For a server, mount an authorized-keys Secret and point
`server.config.auth.authorized_keys_dir` at it:

```yaml
component: server
secretMounts:
  - name: authorized-keys
    secretName: ntwire-authorized-keys
    mountPath: /etc/ntwire/keys
server:
  config:
    listen: {https: ":8443", wireguard: ":51820"}
    tls: {state_dir: /var/lib/ntwire/tls}
    auth: {authorized_keys_dir: /etc/ntwire/keys}
    network: {tunnel_cidr: 100.64.0.0/16}
    tunnels: []
```

Set `component: relay` and configure `relay.config` for a relay, or
`component: client` and configure `client.config` for a persistent
`ntwire connect` workload. The client needs an identity (or OIDC settings)
mounted as a Secret and normally does not create a Service.

The chart's `secretMounts` keeps private keys, TLS material, CA files, and
administrator tokens out of Helm values. The writable state volume defaults
to `emptyDir`; enable `persistence` for durable generated TLS state, client
certificate pins/status, or any selected configuration file paths under
`persistence.mountPath`.

For relay Kubernetes Service discovery, set
`serviceAccount.automountServiceAccountToken: true` and create deliberately
scoped RBAC separately. See `deploy/k8s/relay-discovery-rbac.yaml` and
`docs/RELAY.md`; do not grant cluster-wide API access merely to use the chart.

`service.ports` overrides the selected component defaults. Add optional
metrics, reflector, UDP-relay, or dedicated tenant ports explicitly, and keep
the Service, selected configuration, load balancer, and firewall in agreement.

See [docs/DEPLOYMENT.md](../../../docs/DEPLOYMENT.md) for operating guidance.
