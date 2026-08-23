package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// kubernetesDiscovery is deliberately isolated from the public routing path.
// Shared informers provide list/watch, resource-version recovery and watch
// reconnection; a temporary API outage leaves the last valid registry entry
// intact until an explicit delete is observed.
type kubernetesDiscovery struct {
	cfg      KubernetesConfig
	client   kubernetes.Interface
	registry *Registry
	log      *slog.Logger

	mu       sync.Mutex
	services map[string]*v1.Service
	byID     map[string]string // Service UID -> currently registered hostname
	ns       map[string]*v1.Namespace
}

func newKubernetesDiscovery(cfg KubernetesConfig, client kubernetes.Interface, registry *Registry, log *slog.Logger) *kubernetesDiscovery {
	if log == nil {
		log = slog.Default()
	}
	return &kubernetesDiscovery{cfg: cfg, client: client, registry: registry, log: log, services: map[string]*v1.Service{}, byID: map[string]string{}, ns: map[string]*v1.Namespace{}}
}

func startInClusterKubernetesDiscovery(ctx context.Context, cfg KubernetesConfig, registry *Registry, log *slog.Logger) (*kubernetesDiscovery, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("Kubernetes in-cluster configuration: %w", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("Kubernetes client: %w", err)
	}
	d := newKubernetesDiscovery(cfg, client, registry, log)
	d.Start(ctx)
	return d, nil
}

func (d *kubernetesDiscovery) Start(ctx context.Context) {
	// Use shared informers rather than polling. Services are server-side
	// filtered; Namespace events are a separate unfiltered cache because their
	// labels control scope and must not inherit the Service selector.
	svcFactory := informers.NewFilteredSharedInformerFactory(d.client, 0, metav1.NamespaceAll, func(o *metav1.ListOptions) { o.LabelSelector = d.cfg.Service.Selector })
	services := svcFactory.Core().V1().Services().Informer()
	services.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { d.putService(obj.(*v1.Service)) },
		UpdateFunc: func(_, obj interface{}) { d.putService(obj.(*v1.Service)) },
		DeleteFunc: d.deleteService,
	})
	svcFactory.Start(ctx.Done())
	synced := []cache.InformerSynced{services.HasSynced}
	if d.cfg.Namespaces.Selector != "" {
		nsFactory := informers.NewSharedInformerFactory(d.client, 0)
		namespaces := nsFactory.Core().V1().Namespaces().Informer()
		namespaces.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { d.putNamespace(obj.(*v1.Namespace)) },
			UpdateFunc: func(_, obj interface{}) { d.putNamespace(obj.(*v1.Namespace)) },
			DeleteFunc: d.deleteNamespace,
		})
		nsFactory.Start(ctx.Done())
		synced = append(synced, namespaces.HasSynced)
	}
	go func() {
		if !cache.WaitForCacheSync(ctx.Done(), synced...) {
			d.log.Warn("Kubernetes discovery cache sync interrupted")
			return
		}
		d.log.Info("Kubernetes Service discovery synchronized")
	}()
}

func (d *kubernetesDiscovery) putService(s *v1.Service) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.services[string(s.UID)] = s.DeepCopy()
	d.reconcileLocked(string(s.UID))
}
func (d *kubernetesDiscovery) deleteService(obj interface{}) {
	s, ok := obj.(*v1.Service)
	if !ok {
		s, ok = obj.(cache.DeletedFinalStateUnknown).Obj.(*v1.Service)
		if !ok {
			return
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	id := string(s.UID)
	host := d.byID[id]
	if host == "" {
		host = normalizeSNI(s.Annotations[d.cfg.Registration.HostnameAnnotation])
	}
	if host != "" {
		d.registry.RemoveKubernetes(host, id)
	}
	delete(d.byID, id)
	delete(d.services, id)
	d.log.Info("Kubernetes Service removed", "namespace", s.Namespace, "service", s.Name)
}
func (d *kubernetesDiscovery) putNamespace(n *v1.Namespace) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ns[n.Name] = n.DeepCopy()
	d.reconcileAllLocked()
}
func (d *kubernetesDiscovery) deleteNamespace(obj interface{}) {
	n, ok := obj.(*v1.Namespace)
	if !ok {
		n, ok = obj.(cache.DeletedFinalStateUnknown).Obj.(*v1.Namespace)
		if !ok {
			return
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.ns, n.Name)
	d.reconcileAllLocked()
}
func (d *kubernetesDiscovery) reconcileAllLocked() {
	for id := range d.services {
		d.reconcileLocked(id)
	}
}

func (d *kubernetesDiscovery) reconcileLocked(id string) {
	s := d.services[id]
	old := d.byID[id]
	ep, ok, err := d.endpointLocked(s)
	if err != nil {
		d.log.Warn("Kubernetes Service ignored", "namespace", s.Namespace, "service", s.Name, "error", err)
		ok = false
	}
	if old != "" && (!ok || old != ep.Hostname) {
		d.registry.RemoveKubernetes(old, id)
		delete(d.byID, id)
	}
	if !ok {
		return
	}
	if err := d.registry.UpsertKubernetes(ep); err != nil {
		d.log.Error("Kubernetes hostname conflict; routing disabled", "hostname", ep.Hostname, "namespace", ep.Namespace, "service", ep.Service, "error", err)
		return
	}
	d.byID[id] = ep.Hostname
	d.log.Info("Kubernetes Service discovered", "hostname", ep.Hostname, "namespace", ep.Namespace, "service", ep.Service, "source", SourceKubernetes)
}

func (d *kubernetesDiscovery) endpointLocked(s *v1.Service) (ServerEndpoint, bool, error) {
	if s == nil || !d.allowedNamespaceLocked(s.Namespace) {
		return ServerEndpoint{}, false, nil
	}
	sel, err := labels.Parse(d.cfg.Service.Selector)
	if err != nil || !sel.Matches(labels.Set(s.Labels)) {
		return ServerEndpoint{}, false, nil
	}
	if s.Labels["ntwire.io/relay-enabled"] != "true" {
		return ServerEndpoint{}, false, fmt.Errorf("ntwire.io/relay-enabled=true label is required")
	}
	host := normalizeSNI(s.Annotations[d.cfg.Registration.HostnameAnnotation])
	if !validHostname(host) {
		return ServerEndpoint{}, false, fmt.Errorf("invalid hostname annotation")
	}
	var port int32
	for _, p := range s.Spec.Ports {
		if p.Name == d.cfg.Service.PortName {
			port = p.Port
			break
		}
	}
	if port < 1 || port > 65535 {
		return ServerEndpoint{}, false, fmt.Errorf("required Service port %q is missing", d.cfg.Service.PortName)
	}
	return ServerEndpoint{Hostname: host, Address: net.JoinHostPort(s.Name+"."+s.Namespace+".svc", strconv.Itoa(int(port))), Namespace: s.Namespace, Service: s.Name, Tenant: s.Annotations[d.cfg.Registration.TenantAnnotation], Source: SourceKubernetes, ID: string(s.UID)}, true, nil
}
func (d *kubernetesDiscovery) allowedNamespaceLocked(name string) bool {
	if d.cfg.Namespaces.Mode == "selected" {
		found := false
		for _, n := range d.cfg.Namespaces.Names {
			if n == name {
				found = true
				break
			}
		}
		if !found && d.cfg.Namespaces.Selector == "" {
			return false
		}
	}
	if d.cfg.Namespaces.Selector == "" {
		return true
	}
	sel, err := labels.Parse(d.cfg.Namespaces.Selector)
	if err != nil {
		return false
	}
	n := d.ns[name]
	return n != nil && sel.Matches(labels.Set(n.Labels))
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.Contains(s, "*") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !validLabel(label) || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || len(label) > 63 {
			return false
		}
	}
	return true
}
