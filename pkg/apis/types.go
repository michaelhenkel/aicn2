package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/michaelhenkel/aicn2/pkg/utils"
	"k8s.io/klog"
)

type ClusterNetwork struct {
	Cidr       string `json:"cidr"`
	ClusterID  string `json:"cluster_id"`
	HostPrefix int    `json:"host_prefix"`
}

type Cluster struct {
	token                      string
	assistedServiceAPI         string
	AmsSubscriptionID          string           `json:"ams_subscription_id"`
	BaseDNSDomain              string           `json:"base_dns_domain"`
	ClusterNetworkCidr         string           `json:"cluster_network_cidr"`
	ClusterNetworkHostPrefix   int              `json:"cluster_network_host_prefix"`
	ClusterNetworks            []ClusterNetwork `json:"cluster_networks"`
	ConnectivityMajorityGroups string           `json:"connectivity_majority_groups"`
	ControllerLogsCollectedAt  time.Time        `json:"controller_logs_collected_at"`
	ControllerLogsStartedAt    time.Time        `json:"controller_logs_started_at"`
	CPUArchitecture            string           `json:"cpu_architecture"`
	CreatedAt                  time.Time        `json:"created_at"`
	DiskEncryption             struct {
	} `json:"disk_encryption"`
	EmailDomain          string        `json:"email_domain"`
	FeatureUsage         string        `json:"feature_usage"`
	HighAvailabilityMode string        `json:"high_availability_mode"`
	HostNetworks         interface{}   `json:"host_networks"`
	Hosts                []interface{} `json:"hosts"`
	Href                 string        `json:"href"`
	Hyperthreading       string        `json:"hyperthreading"`
	ID                   string        `json:"id"`
	ImageInfo            struct {
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"image_info"`
	InstallCompletedAt time.Time     `json:"install_completed_at"`
	InstallStartedAt   time.Time     `json:"install_started_at"`
	Kind               string        `json:"kind"`
	MachineNetworks    []interface{} `json:"machine_networks"`
	MachineNetworkCIDR string        `json:"machine_network_cidr"`
	MonitoredOperators []struct {
		ClusterID       string    `json:"cluster_id"`
		Name            string    `json:"name"`
		OperatorType    string    `json:"operator_type"`
		StatusUpdatedAt time.Time `json:"status_updated_at"`
		TimeoutSeconds  int       `json:"timeout_seconds"`
	} `json:"monitored_operators"`
	Name             string     `json:"name"`
	Networking       Networking `json:"networking"`
	OcpReleaseImage  string     `json:"ocp_release_image"`
	OpenshiftVersion string     `json:"openshift_version"`
	OrgID            string     `json:"org_id"`
	Platform         Platform   `json:"platform"`
	Progress         struct {
	} `json:"progress"`
	PullSecretSet      bool   `json:"pull_secret_set"`
	PullSecret         string `json:"pull_secret"`
	SchedulableMasters bool   `json:"schedulable_masters"`
	ServiceNetworkCidr string `json:"service_network_cidr"`
	ServiceNetworks    []struct {
		Cidr      string `json:"cidr"`
		ClusterID string `json:"cluster_id"`
	} `json:"service_networks"`
	Status                string    `json:"status"`
	StatusInfo            string    `json:"status_info"`
	StatusUpdatedAt       time.Time `json:"status_updated_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	UserManagedNetworking bool      `json:"user_managed_networking"`
	UserName              string    `json:"user_name"`
	ValidationsInfo       string    `json:"validations_info"`
	VipDhcpAllocation     bool      `json:"vip_dhcp_allocation"`
	SSHPublicKey          string    `json:"ssh_public_key,omitempty"`
}

type Networking struct {
	NetworkType string `json:"networkType"`
}

type Platform struct {
	Type string `json:"type"`
}

type Token struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

type PullSecret struct {
	Auths struct {
		CloudOpenshiftCom struct {
			Auth  string `json:"auth"`
			Email string `json:"email"`
		} `json:"cloud.openshift.com"`
		QuayIo struct {
			Auth  string `json:"auth"`
			Email string `json:"email"`
		} `json:"quay.io"`
		RegistryConnectRedhatCom struct {
			Auth  string `json:"auth"`
			Email string `json:"email"`
		} `json:"registry.connect.redhat.com"`
		RegistryRedhatIo struct {
			Auth  string `json:"auth"`
			Email string `json:"email"`
		} `json:"registry.redhat.io"`
	} `json:"auths"`
}

func NewCluster(token, assistedServiceAPI string) *Cluster {
	return &Cluster{
		token:              token,
		assistedServiceAPI: assistedServiceAPI,
		Kind:               "Cluster",
		OpenshiftVersion:   "4.8",
		OcpReleaseImage:    "quay.io/openshift-release-dev/ocp-release:4.8.4-x86_64",
		BaseDNSDomain:      "cluster.local",
		Hyperthreading:     "all",
		ClusterNetworkCidr: "10.128.0.0/14",
		ClusterNetworks: []ClusterNetwork{{
			Cidr:       "10.233.64.0/18",
			HostPrefix: 24,
		}},
		ClusterNetworkHostPrefix: 24,
		ServiceNetworkCidr:       "172.30.0.0/16",
		Networking: Networking{
			NetworkType: "Contrail",
		},
		Platform: Platform{
			Type: "baremetal",
		},
		UserManagedNetworking: true,
		VipDhcpAllocation:     false,
		HighAvailabilityMode:  "None",
	}
}

func Get(name, token, assistedServiceAPI string) (*Cluster, error) {
	clusterList, err := List(token, assistedServiceAPI)
	if err != nil {
		return nil, err
	}
	for _, cluster := range clusterList {
		if cluster.Name == name {
			cluster.token = token
			cluster.assistedServiceAPI = assistedServiceAPI
			return &cluster, nil
		}
	}
	return nil, fmt.Errorf("cluster not found")
}

func List(token, assistedServiceAPI string) ([]Cluster, error) {
	header := map[string]string{
		"accept":        "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
	resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters", assistedServiceAPI), "GET", header, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var clusterList []Cluster
	if err := json.Unmarshal(body, &clusterList); err != nil {
		return nil, err
	}
	return clusterList, nil
}

func (c *Cluster) List() ([]Cluster, error) {
	header := map[string]string{
		"accept":        "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", c.token),
	}
	resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters", c.assistedServiceAPI), "GET", header, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var clusterList []Cluster
	if err := json.Unmarshal(body, &clusterList); err != nil {
		return nil, err
	}
	return clusterList, nil
}

func GetToken(offlineToken string) (string, error) {
	dataSet := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     "cloud-services",
		"refresh_token": offlineToken,
	}
	data := url.Values{}

	for k, v := range dataSet {
		data.Set(k, v)
	}
	content := strings.NewReader(data.Encode())

	header := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	contentLength := strconv.Itoa(len(data.Encode()))

	resp, err := utils.HttpRequest("https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token", "POST", header, content, contentLength)
	if err != nil {
		return "", err
	}
	t := &Token{}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(body, t); err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

func (c *Cluster) CreateCluster() error {
	machineNetworkCidr := c.MachineNetworkCIDR
	clusterByte, err := json.Marshal(c)
	if err != nil {
		return err
	}
	content := bytes.NewReader(clusterByte)
	header := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", c.token),
	}
	contentLength := strconv.Itoa(len(clusterByte))
	resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters", c.assistedServiceAPI), "POST", header, content, contentLength)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, c); err != nil {
		return err
	}

	data := map[string]string{"machine_network_cidr": machineNetworkCidr}
	dataByte, err := json.Marshal(&data)
	if err != nil {
		return err
	}
	content = bytes.NewReader(dataByte)
	contentLength = strconv.Itoa(len(dataByte))
	header = map[string]string{
		"accept":        "application/json",
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", c.token),
	}
	resp, err = utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters", c.assistedServiceAPI), "PATCH", header, content, contentLength)
	if err != nil {
		klog.Info(resp)
		return err
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, c); err != nil {
		return err
	}

	return nil
}

func (c *Cluster) DownloadISO() error {
	header := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", c.token),
	}

	resp, err := utils.HttpRequest(fmt.Sprintf("http://%s/api/assisted-install/v1/clusters/%s/downloads/image", c.assistedServiceAPI, c.ID), "GET", header, nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(fmt.Sprintf("%s.iso", c.Name))
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

func (c *Cluster) GenerateISO() error {
	var data struct {
		SSHPublicKey string      `json:"ssh_public_key"`
		PullSecret   *PullSecret `json:"pull_secret"`
	}
	pullSecretByte := []byte(c.PullSecret)
	pullSecret := &PullSecret{}
	if err := json.Unmarshal(pullSecretByte, pullSecret); err != nil {
		return nil
	}
	data.SSHPublicKey = c.SSHPublicKey
	data.PullSecret = pullSecret

	dataByte, err := json.Marshal(data)
	if err != nil {
		return err
	}
	content := bytes.NewReader(dataByte)
	contentLength := strconv.Itoa(len(dataByte))

	header := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", c.token),
	}
	resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters/%s/downloads/image", c.assistedServiceAPI, c.ID), "POST", header, content, contentLength)
	if err != nil {
		klog.Info(resp)
		return err
	}
	return nil
}

func (c *Cluster) Upload(manifestDirectory string) error {
	manifests := findManifests(manifestDirectory, ".yaml")
	for _, manifest := range manifests {
		manifestByte, err := os.ReadFile(manifest)
		if err != nil {
			return err
		}
		encodedString := base64.StdEncoding.EncodeToString([]byte(manifestByte))
		fileName := filepath.Base(manifest)
		data := map[string]string{
			"file_name": fileName,
			"folder":    "manifests",
			"content":   encodedString,
		}
		dataByte, err := json.Marshal(&data)
		if err != nil {
			return err
		}
		content := bytes.NewReader(dataByte)
		contentLength := strconv.Itoa(len(dataByte))
		header := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": fmt.Sprintf("Bearer %s", c.token),
		}

		resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters/%s/manifests", c.assistedServiceAPI, c.ID), "POST", header, content, contentLength)
		if err != nil {
			klog.Error(resp)
			return err
		}
	}
	return nil
}

func (c *Cluster) GetManifests() ([]byte, error) {
	header := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", c.token),
	}
	resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters/%s/manifests", c.assistedServiceAPI, c.ID), "GET", header, nil, "")
	if err != nil {
		klog.Error(resp)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil

}

func findManifests(root, ext string) []string {
	var a []string
	filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ext {
			a = append(a, s)
		}
		return nil
	})
	return a
}
