package relay

import (
	"fmt"
	"sync"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func testKubeConfig() KubernetesConfig {
	var c KubernetesConfig
	c.Enabled = true
	c.Namespaces.Mode = "all"
	c.Service.Selector = "app.kubernetes.io/name=ntwire-server"
	c.Service.PortName = "ntwire-relay"
	c.Registration.HostnameAnnotation = "ntwire.io/hostname"
	c.Registration.TenantAnnotation = "ntwire.io/tenant"
	return c
}

func testService(uid, host string) *v1.Service {
	return &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "ntwire-server", Namespace: "customer-a", UID: types.UID(uid), Labels: map[string]string{"app.kubernetes.io/name": "ntwire-server", "ntwire.io/relay-enabled": "true"}, Annotations: map[string]string{"ntwire.io/hostname": host}}, Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Name: "ntwire-relay", Port: 8443}}}}
}

func TestKubernetesDiscovery_ServiceLifecycleAndConflict(t *testing.T) {
	r := NewRegistry(nil, Limits{})
	d := newKubernetesDiscovery(testKubeConfig(), fake.NewSimpleClientset(), r, nil)
	d.putService(testService("one", "customer-a.ntwire.example.com"))
	ep, ok := r.Lookup("customer-a.ntwire.example.com")
	if !ok || ep.Address != "ntwire-server.customer-a.svc:8443" {
		t.Fatalf("endpoint = %#v, %v", ep, ok)
	}
	d.putService(testService("two", "customer-a.ntwire.example.com"))
	if _, ok := r.Lookup("customer-a.ntwire.example.com"); ok {
		t.Fatal("duplicate hostname must fail closed")
	}
	d.deleteService(testService("two", "customer-a.ntwire.example.com"))
	if _, ok := r.Lookup("customer-a.ntwire.example.com"); !ok {
		t.Fatal("route was not restored after conflict deletion")
	}
	d.deleteService(testService("one", "customer-a.ntwire.example.com"))
	if _, ok := r.Lookup("customer-a.ntwire.example.com"); ok {
		t.Fatal("delete did not remove route")
	}
}

func TestKubernetesDiscovery_FiltersAndValidates(t *testing.T) {
	r := NewRegistry(nil, Limits{})
	c := testKubeConfig()
	c.Namespaces.Mode = "selected"
	c.Namespaces.Names = []string{"customer-b"}
	d := newKubernetesDiscovery(c, fake.NewSimpleClientset(), r, nil)
	d.putService(testService("one", "bad.*.example.com"))
	if len(r.List()) != 0 {
		t.Fatal("out-of-scope or invalid Service registered")
	}
	s := testService("two", "customer-b.ntwire.example.com")
	s.Namespace = "customer-b"
	d.putService(s)
	if _, ok := r.Lookup("customer-b.ntwire.example.com"); !ok {
		t.Fatal("selected namespace Service not registered")
	}
}

func TestRegistryKubernetesUpdate(t *testing.T) {
	r := NewRegistry(nil, Limits{})
	ep := ServerEndpoint{Hostname: "a.example.com", Address: "a.ns.svc:8443", Source: SourceKubernetes, ID: "one"}
	if err := r.UpsertKubernetes(ep); err != nil {
		t.Fatal(err)
	}
	ep.Address = "a.ns.svc:9443"
	if err := r.UpsertKubernetes(ep); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Lookup(ep.Hostname)
	if got.Address != ep.Address {
		t.Fatalf("update = %q", got.Address)
	}
}

func TestRegistryKubernetesConcurrentLookupAndUpdate(t *testing.T) {
	r := NewRegistry(nil, Limits{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("%d.example.com", i)
			for n := 0; n < 50; n++ {
				_ = r.UpsertKubernetes(ServerEndpoint{Hostname: host, Address: "server.ns.svc:8443", Source: SourceKubernetes, ID: fmt.Sprintf("%d", i)})
				_, _ = r.Lookup(host)
			}
		}(i)
	}
	wg.Wait()
}
