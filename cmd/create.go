package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/openshift/assisted-service/client/installer"
	aiManifests "github.com/openshift/assisted-service/client/manifests"
	"github.com/openshift/assisted-service/models"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"k8s.io/klog"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/cn2"
	"github.com/michaelhenkel/aicn2/pkg/infrastructure"
)

var (
	file       string
	noiso      bool
	worker     int
	controller int
)

func init() {
	create.PersistentFlags().StringVarP(&file, "file", "f", "", "access token file")
	create.PersistentFlags().IntVarP(&worker, "worker", "w", 0, "worker count")
	create.PersistentFlags().IntVarP(&controller, "controller", "c", 1, "controller count")
	create.PersistentFlags().BoolVar(&noiso, "noiso", false, "don't create iso")
}

type InstallConfig struct {
	APIVersion string `yaml:"apiVersion"`
	BaseDomain string `yaml:"baseDomain"`
	Networking struct {
		NetworkType    string        `yaml:"networkType"`
		ClusterNetwork []interface{} `yaml:"clusterNetwork"`
		ServiceNetwork []interface{} `yaml:"serviceNetwork"`
	} `yaml:"networking"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Compute []struct {
		Hyperthreading string `yaml:"hyperthreading"`
		Name           string `yaml:"name"`
		Replicas       int    `yaml:"replicas"`
	} `yaml:"compute"`
	ControlPlane struct {
		Hyperthreading string `yaml:"hyperthreading"`
		Name           string `yaml:"name"`
		Replicas       int    `yaml:"replicas"`
	} `yaml:"controlPlane"`
	Platform struct {
		None struct {
		} `yaml:"none"`
		Vsphere interface{} `yaml:"vsphere"`
	} `yaml:"platform"`
	Fips       bool   `yaml:"fips"`
	PullSecret string `yaml:"pullSecret"`
}

var create = &cobra.Command{
	Use:   "create [name]",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if file == "" && len(args) != 1 {
			klog.Fatal("--file or name has to be specified")
		}
		client, err := api.NewClient(token)
		if err != nil {
			klog.Fatal(err)
		}
		clusterList, err := client.Installer.ListClusters(context.Background(), &installer.ListClustersParams{})
		if err != nil {
			klog.Fatal(err)
		}

		var cluster *models.Cluster
		clusterExists := false
		for _, cl := range clusterList.GetPayload() {
			if cl.Name == args[0] {
				clusterExists = true
				cluster = cl
			}
		}
		homedir, err := os.UserHomeDir()
		if err != nil {
			klog.Fatal(err)
		}

		if !clusterExists {
			if file == "" {
				klog.Fatal("--file must be provided")
			}
			fileByte, err := os.ReadFile(file)
			if err != nil {
				klog.Fatal(err)
			}
			ha := false
			if controller+worker > 1 {
				ha = true
			}
			createCluster, err := api.NewCreateCluster(fileByte, ha)
			if err != nil {
				klog.Fatal(err)
			}
			if len(args) == 1 {
				createCluster.Name = &args[0]
			}
			pullSecretByte, err := os.ReadFile(fmt.Sprintf("%s/.aicn2/pull-secret.txt", homedir))
			if err != nil {
				klog.Fatal(err)
			}
			pullSecret := string(pullSecretByte)
			createCluster.PullSecret = &pullSecret
			if createCluster.SSHPublicKey == "" {
				sshPubKeyByte, err := os.ReadFile(fmt.Sprintf("%s/.ssh/id_rsa.pub", homedir))
				if err != nil {
					klog.Fatal(err)
				}
				createCluster.SSHPublicKey = string(sshPubKeyByte)
			}
			klog.Info("Registering Cluster")
			resp, err := client.Installer.RegisterCluster(context.Background(), &installer.RegisterClusterParams{
				NewClusterParams: createCluster,
			})
			if err != nil {
				klog.Fatal(resp, err)
			}
			klog.Info("Getting Cluster")
			clusterList, err := client.Installer.ListClusters(context.Background(), &installer.ListClustersParams{})
			if err != nil {
				klog.Fatal(err)
			}
			for _, cl := range clusterList.GetPayload() {
				if cl.Name == *createCluster.Name {
					cluster = cl
				}
			}
			klog.Info("Generating ISO")
			if _, err := client.Installer.GenerateClusterISO(context.Background(), &installer.GenerateClusterISOParams{
				ClusterID: *cluster.ID,
				ImageCreateParams: &models.ImageCreateParams{
					ImageType:    models.ImageTypeFullIso,
					SSHPublicKey: strings.Trim(createCluster.SSHPublicKey, "\n"),
				},
			}); err != nil {
				klog.Fatal(err)
			}
			if _, err := os.Stat(fmt.Sprintf("%s/.aicn2/%s", homedir, *createCluster.Name)); os.IsNotExist(err) {
				if err := os.Mkdir(fmt.Sprintf("%s/.aicn2/%s", homedir, *createCluster.Name), 0755); err != nil {
					klog.Fatal(err)
				}
			}
			out, err := os.Create(fmt.Sprintf("%s/.aicn2/%s/discover.iso", homedir, *createCluster.Name))
			if err != nil {
				klog.Fatal(err)
			}
			defer out.Close()
			klog.Info("Downloading ISO")
			if _, err := client.Installer.DownloadClusterISO(context.Background(), &installer.DownloadClusterISOParams{
				ClusterID: *cluster.ID,
			}, out); err != nil {
				klog.Fatal(err)
			}
			/*
				ignitionParams := &models.AssistedServiceIsoCreateParams{
					OpenshiftVersion: *createCluster.OpenshiftVersion,
					SSHPublicKey:     strings.Trim(createCluster.SSHPublicKey, "\n"),
					PullSecret:       string(pullSecretByte),
				}
				klog.Info("Creating ISO")
				if _, err := client.AssistedServiceIso.CreateISOAndUploadToS3(context.Background(), &assisted_service_iso.CreateISOAndUploadToS3Params{
					AssistedServiceIsoCreateParams: ignitionParams,
				}); err != nil {
					klog.Fatal(err)
				}
				if _, err := os.Stat(fmt.Sprintf("%s/.aicn2/%s", homedir, *createCluster.Name)); os.IsNotExist(err) {
					if err := os.Mkdir(fmt.Sprintf("%s/.aicn2/%s", homedir, *createCluster.Name), 0755); err != nil {
						klog.Fatal(err)
					}
				}
				out, err := os.Create(fmt.Sprintf("%s/.aicn2/%s/discover.iso", homedir, *createCluster.Name))
				if err != nil {
					klog.Fatal(err)
				}
				defer out.Close()
				klog.Info("Downloading ISO")
				if _, err := client.AssistedServiceIso.DownloadISO(context.Background(), &assisted_service_iso.DownloadISOParams{}, out); err != nil {
					klog.Fatal(err)
				}
			*/
		}

		var infraInterface infrastructure.InfrastructureInterface
		c, err := cn2.New()
		if err != nil {
			klog.Fatal(err)
		}
		infraInterface = c
		klog.Info("Preparing Storage")
		if err := infraInterface.CreateStorage(infrastructure.Image{
			Name: cluster.Name,
			Path: fmt.Sprintf("%s/.aicn2/%s/discover.iso", homedir, cluster.Name),
		}, controller, worker); err != nil {
			klog.Fatal(err)
		}
		klog.Info("Creating VN")
		if err := infraInterface.CreateVN(cluster.Name, cluster.MachineNetworkCidr); err != nil {
			klog.Fatal(err)
		}
		klog.Info("Creating VMs")
		if err := infraInterface.CreateVMS(cluster.Name, controller, worker); err != nil {
			klog.Fatal(err)
		}
		klog.Info("Creating DNS and LB")
		if err := infraInterface.CreateDNSLB(cluster.Name); err != nil {
			klog.Fatal(err)
		}
		klog.Info("Uploading Manifests")
		manifestFiles := findManifests("manifests", ".yaml")
		for _, manifestFile := range manifestFiles {
			manifestByte, err := os.ReadFile(manifestFile)
			if err != nil {
				klog.Fatal(err)
			}
			encodedString := base64.StdEncoding.EncodeToString([]byte(manifestByte))
			fileName := filepath.Base(manifestFile)
			folder := "manifests"
			manifest := &models.CreateManifestParams{
				Content:  &encodedString,
				FileName: &fileName,
				Folder:   &folder,
			}
			clusterManifest := &aiManifests.CreateClusterManifestParams{
				CreateManifestParams: manifest,
				ClusterID:            *cluster.ID,
			}

			if _, err := client.Manifests.CreateClusterManifest(context.Background(), clusterManifest); err != nil {
				klog.Fatal(err)
			}
		}

		installConfigOK, err := client.Installer.GetClusterInstallConfig(context.Background(), &installer.GetClusterInstallConfigParams{
			ClusterID: *cluster.ID,
		})
		if err != nil {
			klog.Fatal(err)
		}

		installConfigPayload := installConfigOK.GetPayload()
		installConfig := &InstallConfig{}
		if err := yaml.Unmarshal([]byte(installConfigPayload), installConfig); err != nil {
			klog.Fatal(err)
		}
		installConfig.Networking.NetworkType = "Contrail"
		//installConfigByte, err := yaml.Marshal(installConfig)
		if err != nil {
			klog.Fatal(err)
		}
		updateClusterConfigParams := installer.NewUpdateClusterInstallConfigParams()
		updateClusterConfigParams.SetClusterID(*cluster.ID)
		//updateClusterConfigParams.SetInstallConfigParams(`"{\"networking\":{\"networkType\":\"Contrail\"}}"`)
		updateClusterConfigParams.SetInstallConfigParams(`{"networking":{"networkType":"Contrail"}}`)
		klog.Info("Setting Network Type")
		if _, err := client.Installer.UpdateClusterInstallConfig(context.Background(), updateClusterConfigParams); err != nil {
			klog.Fatal(err)
		}
		fmt.Println("done")

		/*
			klog.Info("Setting MaschineNetwork")
			if err := cluster.SetMachineNetwork(); err != nil {
				klog.Fatal(err)
			}

				klog.Info("Waiting for Discovery")
				if err := cluster.WaitForReady(cluster.Name); err != nil {
					klog.Fatal(err)
				}

				klog.Info("Starting Installation")
				if err := cluster.StartInstallation(cluster.Name); err != nil {
					klog.Fatal(err)
				}
		*/
	},
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
