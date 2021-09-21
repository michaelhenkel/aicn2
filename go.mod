module github.com/michaelhenkel/aicn2

go 1.16

require (
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.1.0
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/onsi/ginkgo v1.14.2 // indirect
	github.com/onsi/gomega v1.10.3 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/cobra v1.2.1
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	k8s.io/api v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.10.0 // indirect
	//kubevirt.io/client-go v0.41.0-rc.0.0.20210602203928-edb77f316136
	kubevirt.io/client-go v0.44.1
	ssd-git.juniper.net/contrail/cn2/contrail v0.0.0-00010101000000-000000000000
)

replace (
	github.com/containers/podman/v2 => github.com/containers/libpod/v2 v2.2.1
	github.com/go-kit/kit => github.com/go-kit/kit v0.3.0
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1
	//github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.3.1
	github.com/openshift/api => github.com/openshift/api v0.0.0-20210105115604-44119421ec6b
	github.com/openshift/client-go => github.com/openshift/client-go v0.0.0-20210112165513-ebc401615f47
	github.com/operator-framework/operator-lifecycle-manager => github.com/operator-framework/operator-lifecycle-manager v0.0.0-20190128024246-5eb7ae5bdb7a
	google.golang.org/grpc => google.golang.org/grpc v1.29.1
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.4
	//k8s.io/klog => k8s.io/klog v2.10.0
	k8s.io/api => k8s.io/api v0.20.2
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.20.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.20.2
	k8s.io/apiserver => k8s.io/apiserver v0.20.2
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.20.2
	k8s.io/client-go => k8s.io/client-go v0.20.2
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.20.2
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.20.2
	k8s.io/code-generator => k8s.io/code-generator v0.20.2
	k8s.io/component-base => ./third_party/component-base
	//k8s.io/component-base => k8s.io/component-base v0.20.2
	k8s.io/cri-api => k8s.io/cri-api v0.20.2
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.20.2
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.20.2
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.20.2
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20210113233702-8566a335510f
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.20.2
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.20.2
	k8s.io/kubectl => k8s.io/kubectl v0.20.2
	k8s.io/kubelet => k8s.io/kubelet v0.20.2
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.20.2
	k8s.io/metrics => k8s.io/metrics v0.20.2
	k8s.io/node-api => k8s.io/node-api v0.20.2
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.20.2
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.20.2
	k8s.io/sample-controller => k8s.io/sample-controller v0.20.2
	kubevirt.io/containerized-data-importer => kubevirt.io/containerized-data-importer v1.37.1
	sigs.k8s.io/structured-merge-diff => sigs.k8s.io/structured-merge-diff v0.0.0-20190302045857-e85c7b244fd2
	ssd-git.juniper.net/contrail/cn2/contrail => ../../../ssd-git.juniper.net/contrail/cn2/contrail

	ssd-git.juniper.net/contrail/cn2/third_party/apiserver-builder-alpha => ../../../ssd-git.juniper.net/contrail/cn2/third_party/apiserver-builder-alpha
)
