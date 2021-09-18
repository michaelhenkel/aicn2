package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/klog"
)

type method string

const (
	assistedServiceAPI        = "api.openshift.com"
	POST               method = "POST"
	GET                method = "GET"
	DELETE             method = "DELETE"
)

type ClusterNetwork struct {
	Cidr       string `json:"cidr"`
	ClusterID  string `json:"cluster_id"`
	HostPrefix int    `json:"host_prefix"`
}

type Cluster struct {
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
	MonitoredOperators []struct {
		ClusterID       string    `json:"cluster_id"`
		Name            string    `json:"name"`
		OperatorType    string    `json:"operator_type"`
		StatusUpdatedAt time.Time `json:"status_updated_at"`
		TimeoutSeconds  int       `json:"timeout_seconds"`
	} `json:"monitored_operators"`
	Name             string `json:"name"`
	OcpReleaseImage  string `json:"ocp_release_image"`
	OpenshiftVersion string `json:"openshift_version"`
	OrgID            string `json:"org_id"`
	Platform         struct {
		Type    string `json:"type"`
		Vsphere struct {
		} `json:"vsphere"`
	} `json:"platform"`
	Progress struct {
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

func NewCluster() *Cluster {
	return &Cluster{
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
		ServiceNetworkCidr:    "172.30.0.0/16",
		UserManagedNetworking: true,
		VipDhcpAllocation:     false,
		HighAvailabilityMode:  "None",
	}
}

func (c *ClusterList) String() (string, error) {
	tbyte, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(tbyte), nil
}

type ClusterList []struct {
	Cluster
}

func (c *Cluster) Get(name string) {

}

func (c *Cluster) List() (*ClusterList, error) {
	header := map[string]string{
		"accept":        "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
	resp, err := httpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters", assistedServiceAPI), "GET", nil, header, nil)
	if err != nil {
		return nil, err
	}
	clusterList := &ClusterList{}
	if err := json.Unmarshal(resp, clusterList); err != nil {
		return nil, err
	}
	return clusterList, nil
}

var (
	offlineToken string
	token        string
	file         string
)

var rootCmd = &cobra.Command{
	Use: "aicn2",
}

func httpRequest(endpoint string, m string, dataSets map[string]string, header map[string]string, dataContent []byte) ([]byte, error) {
	data := url.Values{}
	var bodyContent io.Reader

	if len(dataSets) > 0 {
		for k, v := range dataSets {
			data.Set(k, v)
		}
		bodyContent = strings.NewReader(data.Encode())
	}

	client := &http.Client{}
	r, err := http.NewRequest(m, endpoint, bodyContent) // URL-encoded payload
	if err != nil {
		return nil, err
	}
	if len(header) > 0 {
		for k, v := range header {
			r.Header.Add(k, v)
		}
	}
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	res, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func getToken() error {
	if offlineToken == "" {
		offlineToken = os.Getenv("OFFLINE_TOKEN")
		if offlineToken == "" {
			offlineTokenByte, err := os.ReadFile(".offlinetoken")
			if err != nil {
				return fmt.Errorf("cannot access offline token")
			}
			offlineToken = strings.TrimRight(string(offlineTokenByte), "\n")
		}
	}

	dataSet := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     "cloud-services",
		"refresh_token": offlineToken,
	}

	header := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	resp, err := httpRequest("https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token", "POST", dataSet, header, nil)
	if err != nil {
		return err
	}
	t := &Token{}
	if err := json.Unmarshal(resp, t); err != nil {
		return err
	}
	token = t.AccessToken
	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&offlineToken, "offlinetoken", "", "access token file")
	create.PersistentFlags().StringVar(&file, "file", "", "access token file")
	rootCmd.AddCommand(create)
	rootCmd.AddCommand(delete)
	rootCmd.AddCommand(get)
	rootCmd.AddCommand(list)
}

func initConfig() {
	if err := getToken(); err != nil {
		klog.Fatal("--offlinetoken must be provided or ACCESS_TOKEN env set or available in .offlinetoken ", err)
	}
}

var create = &cobra.Command{
	Use:   "create [name]",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cluster := NewCluster()
		if file == "" && len(args) != 1 {
			klog.Fatal("--file or name has to be specified")
		}
		if file != "" {
			fileByte, err := os.ReadFile(file)
			if err != nil {
				klog.Fatal(err)
			}
			if err := json.Unmarshal(fileByte, cluster); err != nil {
				klog.Fatal(err)
			}
		}
		if len(args) == 1 {
			cluster.Name = args[0]
		}
		if cluster.PullSecret == "" {
			pullSecretByte, err := os.ReadFile("pull-secret.txt")
			if err != nil {
				klog.Fatal(err)
			}
			cluster.PullSecret = string(pullSecretByte)
		}
		if cluster.SSHPublicKey == "" {
			homedir, err := os.UserHomeDir()
			if err != nil {
				klog.Fatal(err)
			}
			sshPubKeyByte, err := os.ReadFile(fmt.Sprintf("%s/.ssh/id_rsa.pub", homedir))
			if err != nil {
				klog.Fatal(err)
			}
			cluster.SSHPublicKey = string(sshPubKeyByte)
		}
		clusterList, err := cluster.List()
		if err != nil {
			klog.Fatal(err)
		}
		for _, cl := range *clusterList {
			if cl.Name == cluster.Name {
				klog.Fatal("cluster already exists")
			}
		}
		clusterByte, err := json.Marshal(cluster)
		if err != nil {
			klog.Fatal(err)
		}
		header := map[string]string{
			"accept":        "application/json",
			"Authorization": fmt.Sprintf("Bearer %s", token),
		}
		resp, err := httpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters", assistedServiceAPI), "POST", nil, header, clusterByte)
		if err != nil {
			klog.Fatal(err)
		}
		fmt.Println(string(resp))
	},
}

var delete = &cobra.Command{
	Use:   "delete [name]",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			klog.Fatal("name is missing")
		}
		cluster := NewCluster()
		clusterList, err := cluster.List()
		if err != nil {
			klog.Fatal(err)
		}
		for _, cl := range *clusterList {
			if cl.Name == args[0] {
				header := map[string]string{
					"accept":        "application/json",
					"Authorization": fmt.Sprintf("Bearer %s", token),
				}
				resp, err := httpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters/%s", assistedServiceAPI, cl.ID), "DELETE", nil, header, nil)
				if err != nil {
					klog.Fatal(err)
				}
				fmt.Println(string(resp))
			}
		}
	},
}

var get = &cobra.Command{
	Use:   "get [name]",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			klog.Fatal("name is missing")
		}
		cluster := NewCluster()
		clusterList, err := cluster.List()
		if err != nil {
			klog.Fatal(err)
		}
		for _, cl := range *clusterList {
			if cl.Name == args[0] {
				fmt.Println(cl)
			}
		}
	},
}

var list = &cobra.Command{
	Use:   "list",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cluster := NewCluster()
		clusterList, err := cluster.List()
		if err != nil {
			klog.Fatal(err)
		}
		fmt.Println(clusterList.String())
	},
}
