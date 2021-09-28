package api

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"

	rtClient "github.com/go-openapi/runtime/client"
	"github.com/michaelhenkel/aicn2/pkg/utils"
	"github.com/openshift/assisted-service/client"
	"github.com/openshift/assisted-service/client/installer"
	"github.com/openshift/assisted-service/models"
	"k8s.io/klog"
)

const (
	DefaultHost     string = "api.openshift.com"
	DefaultBasePath string = "/api/assisted-install"
)

func ClusterList(token string) error {
	authWriter := rtClient.BearerToken(token)
	aiClient := client.New(client.Config{
		AuthInfo: authWriter,
	})
	installerClient := aiClient.Installer
	clusterList, err := installerClient.ListClusters(context.Background(), &installer.ListClustersParams{})
	if err != nil {
		return err
	}
	for _, cluster := range clusterList.GetPayload() {
		klog.Info(cluster)
	}
	return nil
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

func NewClient(token string) (*client.AssistedInstall, error) {
	authWriter := rtClient.BearerToken(token)
	aiClient := client.New(client.Config{
		AuthInfo: authWriter,
	})

	return aiClient, nil
}

func NewCreateCluster(clusterConfig []byte, ha bool) (*models.ClusterCreateParams, error) {
	cluster := &models.ClusterCreateParams{}
	if err := json.Unmarshal(clusterConfig, cluster); err != nil {
		return nil, err
	}
	userManagedNetworking := true
	cluster.UserManagedNetworking = &userManagedNetworking
	vipDhcpAllocation := false
	cluster.VipDhcpAllocation = &vipDhcpAllocation
	if cluster.OpenshiftVersion == nil {
		version := "4.8"
		cluster.OpenshiftVersion = &version
	}
	if cluster.OcpReleaseImage == "" {
		cluster.OcpReleaseImage = "quay.io/openshift-release-dev/ocp-release:4.8.4-x86_64"
	}
	if cluster.BaseDNSDomain == "" {
		cluster.BaseDNSDomain = "cluster.local"
	}
	if cluster.Hyperthreading == nil {
		hyperthreading := "all"
		cluster.Hyperthreading = &hyperthreading
	}
	if cluster.ClusterNetworkCidr == nil {
		clusterNetworkCidr := "10.128.0.0/14"
		cluster.ClusterNetworkCidr = &clusterNetworkCidr
	}
	if cluster.ClusterNetworkHostPrefix == 0 {
		cluster.ClusterNetworkHostPrefix = 24
	}
	if cluster.ServiceNetworkCidr == nil {
		serviceNetworkCidr := "172.30.0.0/16"
		cluster.ServiceNetworkCidr = &serviceNetworkCidr
	}
	if cluster.Platform == nil {
		platform := &models.Platform{
			Type: models.PlatformTypeBaremetal,
		}
		cluster.Platform = platform
	}
	highavailabiltyMode := "None"
	if ha {
		highavailabiltyMode = "Full"
	}
	cluster.HighAvailabilityMode = &highavailabiltyMode

	return cluster, nil
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
