# ntwire Kubernetes example

These manifests deploy one `ntwire-server` with a ConfigMap, authorized-key
Secret, Service, and NetworkPolicy. They are a template: review every listener,
tunnel, endpoint, image tag, and policy before applying it to a cluster.

## Prepare configuration and credentials

Edit `configmap.yaml` to set a publicly reachable
`network.advertised_endpoint` and define only the tunnels your users need.
Create the Secret expected by `deployment.yaml` from one or more public SSH
keys:

```sh
kubectl create secret generic ntwire-authorized-keys \
  --from-file=authorized_keys=~/.ntwire/id_ed25519.pub
```

Use a namespace-specific command (add `-n <namespace>`) if you customize the
manifests for another namespace. Do not put private keys in a ConfigMap or Git.

## Deploy and verify

Apply the base manifests from this directory:

```sh
kubectl apply -k .
kubectl rollout status deployment/ntwire-server
kubectl get pods,svc
kubectl logs deployment/ntwire-server
```

The Service is `ClusterIP` by default. Configure an ingress, load balancer, or
other suitable exposure method for both TCP 8443 and UDP 51820, then ensure
`advertised_endpoint` matches the client-visible UDP address.

## Relay discovery example

`relay-discovery-example.yaml`, `relay-discovery-rbac.yaml`, and
`relay-discovery-networkpolicy.yaml` are separate, opt-in templates for a
relay that discovers explicitly labelled tenant services. Apply them only after
setting namespaces, hostnames, tenant names, registrations, image tags, and
least-privilege RBAC to match your cluster.

For production TLS, OIDC, relay, and NetworkPolicy design, see
[docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md),
[docs/RELAY.md](../../docs/RELAY.md), and
[docs/SECURITY.md](../../docs/SECURITY.md).
