package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/machinebox/progress"
	"github.com/openshift/assisted-service/client/installer"
	aiManifests "github.com/openshift/assisted-service/client/manifests"
	"github.com/openshift/assisted-service/models"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
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
	nocontrail bool
)

func init() {
	create.PersistentFlags().StringVarP(&file, "file", "f", "", "access token file")
	create.PersistentFlags().IntVarP(&worker, "worker", "w", 0, "worker count")
	create.PersistentFlags().IntVarP(&controller, "controller", "c", 1, "controller count")
	create.PersistentFlags().BoolVar(&noiso, "noiso", false, "don't create iso")
	create.PersistentFlags().BoolVar(&nocontrail, "nocontrail", false, "don't install contrail")
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
			klog.Info("Setting Discovery Kernel Arg")
			if _, err := client.Installer.UpdateDiscoveryIgnition(context.Background(), &installer.UpdateDiscoveryIgnitionParams{
				ClusterID: *cluster.ID,
				DiscoveryIgnitionParams: &models.DiscoveryIgnitionParams{
					Config: `{"ignition":{"version":"3.1.0"},"kernelArguments":{"shouldExist":["ipv6.disable=1"]}}`,
				},
			}); err != nil {
				klog.Fatalf("%+v\n", err)
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

			klog.Info("Downloading ISO")

			attempt := 1
			success := false
			for !success {
				isoHeaderResp, err := client.Installer.DownloadClusterISOHeaders(context.Background(), &installer.DownloadClusterISOHeadersParams{
					ClusterID: *cluster.ID,
				})
				if err != nil {
					klog.Fatal(err)
				}
				out, err := os.Create(fmt.Sprintf("%s/.aicn2/%s/discover.iso", homedir, *createCluster.Name))
				if err != nil {
					klog.Fatal(err)
				}
				defer out.Close()
				progressWriter := progress.NewWriter(out)
				ctx := context.Background()
				go func() {

					progressChan := progress.NewTicker(ctx, progressWriter, isoHeaderResp.ContentLength, 1*time.Second)
					for p := range progressChan {
						//fmt.Printf("\r%v remaining...", p.Remaining().Round(time.Second))
						fmt.Printf("\r%v remaining. %d of %d written...", p.Remaining().Round(time.Second), p.N(), isoHeaderResp.ContentLength)
					}
					fmt.Println("\rdownload is completed")
				}()
				if _, err := client.Installer.DownloadClusterISO(context.Background(), &installer.DownloadClusterISOParams{
					ClusterID: *cluster.ID,
				}, progressWriter); err != nil {
					klog.Errorf("%d attempt of 5 failed with err %+v. Retrying\n", attempt, err)
					ctx.Done()
					if _, err := os.Stat(fmt.Sprintf("%s/.aicn2/%s/discover.iso", homedir, *createCluster.Name)); err == nil {
						if err := os.Remove(fmt.Sprintf("%s/.aicn2/%s/discover.iso", homedir, *createCluster.Name)); err != nil {
							klog.Error(err)
						}
					}
					if attempt == 5 {
						klog.Fatal(err)
					}
					attempt++

				} else {
					success = true
				}

			}
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
		if !nocontrail {
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
		}

		installConfigOK, err := client.Installer.GetClusterInstallConfig(context.Background(), &installer.GetClusterInstallConfigParams{
			ClusterID: *cluster.ID,
		})
		if err != nil {
			klog.Fatal(err)
		}

		installConfigPayload := installConfigOK.GetPayload()
		if !nocontrail {
			installConfig := &InstallConfig{}
			if err := yaml.Unmarshal([]byte(installConfigPayload), installConfig); err != nil {
				klog.Fatal(err)
			}
			installConfig.Networking.NetworkType = "Contrail"
			if err != nil {
				klog.Fatal(err)
			}
			updateClusterConfigParams := installer.NewUpdateClusterInstallConfigParams()
			updateClusterConfigParams.SetClusterID(*cluster.ID)
			updateClusterConfigParams.SetInstallConfigParams(`{"networking":{"networkType":"Contrail"}}`)
			klog.Info("Setting Network Type")
			if _, err := client.Installer.UpdateClusterInstallConfig(context.Background(), updateClusterConfigParams); err != nil {
				klog.Fatal(err)
			}
		}
		klog.Info("Waiting for Host Discovery")
		for {
			listHostsOK, err := client.Installer.ListHosts(context.Background(), &installer.ListHostsParams{
				ClusterID: *cluster.ID,
			})
			if err != nil {
				klog.Fatal(err)
			}
			client.Installer.V2UpdateHostInstallerArgs(context.Background(), &installer.V2UpdateHostInstallerArgsParams{
				InstallerArgsParams: &models.InstallerArgsParams{},
			})
			hostList := listHostsOK.GetPayload()
			if len(hostList) == worker+controller {
				var hostRoles []*models.ClusterUpdateParamsHostsRolesItems0
				for _, host := range hostList {
					/*
						if _, err := client.Installer.V2UpdateHostIgnition(context.Background(), &installer.V2UpdateHostIgnitionParams{
							HostIgnitionParams: &models.HostIgnitionParams{
								Config: kernelIngnitionParam,
							},
							HostID:     *host.ID,
							InfraEnvID: *cluster.ID,
						}); err != nil {
							klog.Fatal(err)
						}
					*/
					if _, err := client.Installer.UpdateHostInstallerArgs(context.Background(), &installer.UpdateHostInstallerArgsParams{
						ClusterID: *cluster.ID,
						HostID:    *host.ID,
						InstallerArgsParams: &models.InstallerArgsParams{
							Args: []string{"--append-karg", "ipv6.disable=1"},
						},
					}); err != nil {
						klog.Fatal(err)
					}
					/*
						kernelIngnitionParam := `{"ignition":{"version":"3.1.0"},"kernelArguments":{"shouldExist":["ipv6.disable","1"]}}`
						if _, err := client.Installer.UpdateHostIgnition(context.Background(), &installer.UpdateHostIgnitionParams{
							ClusterID: *cluster.ID,
							HostID:    *host.ID,
							HostIgnitionParams: &models.HostIgnitionParams{
								Config: kernelIngnitionParam,
							},
						}); err != nil {
							klog.Fatal(err)
						}
					*/
					hostnameList := strings.Split(host.RequestedHostname, "-")
					if len(hostnameList) == 3 {
						if hostnameList[1] == "worker" {
							hostRoles = append(hostRoles, &models.ClusterUpdateParamsHostsRolesItems0{
								ID:   *host.ID,
								Role: models.HostRoleUpdateParamsWorker,
							})
						}
						if hostnameList[1] == "controller" {
							hostRoles = append(hostRoles, &models.ClusterUpdateParamsHostsRolesItems0{
								ID:   *host.ID,
								Role: models.HostRoleUpdateParamsMaster,
							})
						}
					}
				}
				if len(hostRoles) == worker+controller {
					klog.Info("Updating Host Roles")
					if _, err := client.Installer.UpdateCluster(context.Background(), &installer.UpdateClusterParams{
						ClusterID: *cluster.ID,
						ClusterUpdateParams: &models.ClusterUpdateParams{
							HostsRoles: hostRoles,
						},
					}); err != nil {
						klog.Fatal(err)
					}
					break
				}
			}
			time.Sleep(time.Second * 3)
		}

		klog.Info("Waiting for Cluster Ready")
		for {
			currentCluster, err := client.Installer.GetCluster(context.Background(), &installer.GetClusterParams{
				ClusterID: *cluster.ID,
			})
			if err != nil {
				klog.Fatal(err)
			}
			status := currentCluster.GetPayload().Status
			if *status == "ready" {
				break
			}
			time.Sleep(time.Second * 3)
		}

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

func remoteRun(user string, addr string, privateKey string, cmd string) (string, error) {
	// privateKey could be read from a file, or retrieved from another storage
	// source, such as the Secret Service / GNOME Keyring
	key, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return "", err
	}
	// Authentication
	config := &ssh.ClientConfig{
		User: user,
		// https://github.com/golang/go/issues/19767
		// as clientConfig is non-permissive by default
		// you can set ssh.InsercureIgnoreHostKey to allow any host
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		//alternatively, you could use a password
		/*
		   Auth: []ssh.AuthMethod{
		       ssh.Password("PASSWORD"),
		   },
		*/
	}
	// Connect
	client, err := ssh.Dial("tcp", net.JoinHostPort(addr, "22"), config)
	if err != nil {
		return "", err
	}
	// Create a session. It is one session per command.
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var b bytes.Buffer  // import "bytes"
	session.Stdout = &b // get output
	// you can also pass what gets input to the stdin, allowing you to pipe
	// content from client to server
	//      session.Stdin = bytes.NewBufferString("My input")

	// Finally, run the command
	err = session.Run(cmd)
	return b.String(), err
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
