package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
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
	file                  string
	skipiso               bool
	skipstorage           bool
	worker                int
	controller            int
	nocontrail            bool
	registry              string
	memory                string
	vcpu                  uint32
	dedicatedCpuPlacement bool
	modifyHosts           bool
)

func init() {
	create.PersistentFlags().StringVarP(&file, "file", "f", "", "access token file")
	create.PersistentFlags().IntVarP(&worker, "worker", "w", 0, "worker count")
	create.PersistentFlags().IntVarP(&controller, "controller", "c", 1, "controller count")
	create.PersistentFlags().BoolVar(&skipiso, "skipiso", false, "don't create iso")
	create.PersistentFlags().BoolVar(&skipstorage, "skipstorage", false, "don't push containers")
	create.PersistentFlags().BoolVar(&nocontrail, "nocontrail", false, "don't install contrail")
	create.PersistentFlags().StringVarP(&registry, "registry", "r", "registry.default.svc.cluster1.local:5000", "container registry for ISO")
	create.PersistentFlags().StringVarP(&memory, "memory", "m", "16Gi", "VM Memory")
	create.PersistentFlags().Uint32VarP(&vcpu, "vcpu", "v", 8, "VM VCPU")
	create.PersistentFlags().BoolVarP(&dedicatedCpuPlacement, "dedicatedCpuPlacement", "d", false, "enable dedicated CPU placement")
	create.PersistentFlags().BoolVarP(&modifyHosts, "modifyhosts", "e", false, "add entry to /etc/hosts (sudo required)")
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
		var infraInterface infrastructure.InfrastructureInterface
		c, err := cn2.New(registry, kubeconfigPath)
		if err != nil {
			klog.Fatal(err)
		}
		infraInterface = c
		clusterDomain, err := c.GetClusterDomain(args[0])
		if err != nil {
			klog.Fatal(err)
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
			createCluster, err := api.NewCreateCluster(fileByte, clusterDomain, ha)
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
			serviceScript := `#!/bin/bash
success=0
until [ $success -gt 1 ]; do
  tmp=$(mktemp)
  cat <<EOF>${tmp} || true
data:
  requestheader-client-ca-file: |
$(while IFS= read -a line; do echo "    $line"; done < <(cat /etc/kubernetes/bootstrap-secrets/aggregator-ca.crt))
EOF
  KUBECONFIG=/etc/kubernetes/bootstrap-secrets/kubeconfig kubectl -n kube-system patch configmap extension-apiserver-authentication --patch-file ${tmp}
  if [[ $? -eq 0 ]]; then
	rm ${tmp}
	success=2
  fi
  rm ${tmp}
  sleep 60
done`
			encodedScript := base64.StdEncoding.EncodeToString([]byte(serviceScript))
			ingitionConfig := fmt.Sprintf(`{
	"ignition": { "version": "3.1.0" },
	"systemd": {
		"units": [{
			"name": "ca-patch.service",
			"enabled": true,
			"contents": "[Service]\nType=oneshot\nExecStart=/usr/local/bin/ca-patch.sh\n\n[Install]\nWantedBy=multi-user.target"
	  	}]
	},
	"storage": {
		"files": [{
			"path": "/usr/local/bin/ca-patch.sh",
			"mode": 720,
			"contents": { "source": "data:text/plain;charset=utf-8;base64,%s" }
		}]
	},
	"kernelArguments": {
		"shouldExist":["ipv6.disable=1"]
	},
	"passwd": {
		"users": [{
			"name": "core",
			"passwordHash": "%s"
		}]
	}
}`, encodedScript, encryptPassword("contrail123"))
			klog.Info("Setting Discovery Kernel Arg and CA Patch Service")
			if _, err := client.Installer.UpdateDiscoveryIgnition(context.Background(), &installer.UpdateDiscoveryIgnitionParams{
				ClusterID: *cluster.ID,
				DiscoveryIgnitionParams: &models.DiscoveryIgnitionParams{
					Config: ingitionConfig,
				},
			}); err != nil {
				klog.Fatalf("%+v\n", err)
			}

			if !skipiso {
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
					out, err := os.Create(fmt.Sprintf("%s/.aicn2/%s/disk.img", homedir, *createCluster.Name))
					if err != nil {
						klog.Fatal(err)
					}
					defer out.Close()
					progressWriter := progress.NewWriter(out)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					go func() {
						progressChan := progress.NewTicker(ctx, progressWriter, isoHeaderResp.ContentLength, 1*time.Second)
						var previousTime time.Time
						var previousByte int64
						for p := range progressChan {
							select {
							case <-ctx.Done():
								return
							default:
								var bytePerSec int64
								if previousByte != 0 {
									transferedBytes := p.N() - previousByte
									duration := time.Since(previousTime).Milliseconds()
									if duration > 0 && transferedBytes > 0 {
										durationSec := duration / 1000
										transferedKbytes := transferedBytes / 1024
										if durationSec > 0 && transferedKbytes > 0 {
											bytePerSec = transferedKbytes / durationSec
										}

									}
								}
								fmt.Printf("\r%v remaining. %d of %d written... %d kbyte/sec", p.Remaining().Round(time.Second), p.N()/1024, isoHeaderResp.ContentLength/1024, bytePerSec)
								previousByte = p.N()
								previousTime = time.Now()
							}
						}
					}()
					if _, err := client.Installer.DownloadClusterISO(context.Background(), &installer.DownloadClusterISOParams{
						ClusterID: *cluster.ID,
					}, progressWriter); err != nil {
						fmt.Println()
						klog.Errorf("%d attempt of 5 failed with err %+v. Retrying\n", attempt, err)
						cancel()
						if _, err := os.Stat(fmt.Sprintf("%s/.aicn2/%s/disk.img", homedir, *createCluster.Name)); err == nil {
							if err := os.Remove(fmt.Sprintf("%s/.aicn2/%s/disk.img", homedir, *createCluster.Name)); err != nil {
								klog.Error(err)
							}
						}
						if attempt == 5 {
							cancel()
							klog.Fatal(err)
						}
						attempt++

					} else {
						cancel()
						fmt.Println("\rdownload is completed")
						out.Close()
						success = true
					}
				}
			}
		}
		if !skipstorage {
			klog.Info("Preparing Storage")
			if err := infraInterface.CreateStorage(infrastructure.Image{
				Name: cluster.Name,
				Path: fmt.Sprintf("%s/.aicn2/%s/disk.img", homedir, cluster.Name),
			}, controller, worker); err != nil {
				klog.Fatal(err)
			}
		}

		klog.Info("Creating VN")
		if err := infraInterface.CreateVN(cluster.Name, "10.0.0.0/24"); err != nil {
			klog.Fatal(err)
		}

		klog.Info("Creating VMs")
		if err := infraInterface.CreateVMS(cluster.Name, clusterDomain, controller, worker, memory, vcpu, dedicatedCpuPlacement); err != nil {
			klog.Fatal(err)
		}
		/*
			klog.Info("Creating DNS and LB")
			if err := infraInterface.CreateDNSLB(cluster.Name, clusterDomain, modifyHosts); err != nil {
				klog.Fatal(err)
			}
		*/
		klog.Info("Creating API VIP")
		apiVIP, err := infraInterface.AllocateAPIVip(cluster.Name, "api")
		if err != nil {
			klog.Fatal(err)
		}
		klog.Info("Creating Ingress VIP")
		ingressVIP, err := infraInterface.AllocateAPIVip(cluster.Name, "ingress")
		if err != nil {
			klog.Fatal(err)
		}
		klog.Info("Associating API VIP with controller VMs")
		if err := infraInterface.AssociateVip(cluster.Name, apiVIP, "controller"); err != nil {
			klog.Fatal(err)
		}
		klog.Info("Associating Ingress VIP with Worker VMs")
		if err := infraInterface.AssociateVip(cluster.Name, ingressVIP, "worker"); err != nil {
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
						if _, err := client.Installer.UpdateHostInstallerArgs(context.Background(), &installer.UpdateHostInstallerArgsParams{
							ClusterID: *cluster.ID,
							HostID:    *host.ID,
							InstallerArgsParams: &models.InstallerArgsParams{
								Args: []string{"--append-karg", "ipv6.disable=1"},
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
					usermanagedNetwork := false
					if _, err := client.Installer.UpdateCluster(context.Background(), &installer.UpdateClusterParams{
						ClusterID: *cluster.ID,
						ClusterUpdateParams: &models.ClusterUpdateParams{
							HostsRoles:            hostRoles,
							APIVip:                &apiVIP,
							IngressVip:            &ingressVIP,
							UserManagedNetworking: &usermanagedNetwork,
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
				klog.Info("Cluster Ready, starting Installation")
				_, err = client.Installer.InstallCluster(context.Background(), &installer.InstallClusterParams{
					ClusterID: *cluster.ID,
				})
				if err != nil {
					klog.Fatal(err)
				}
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

func encryptPassword(userPassword string) string {
	// Generate a random string for use in the salt
	const charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	s := make([]byte, 8)
	for i := range s {
		s[i] = charset[seededRand.Intn(len(charset))]
	}
	salt := []byte(fmt.Sprintf("$6$%s", s))
	// use salt to hash user-supplied password
	c := sha512_crypt.New()
	hash, err := c.Generate([]byte(userPassword), salt)
	if err != nil {
		fmt.Printf("error hashing user's supplied password: %s\n", err)
		os.Exit(1)
	}
	return string(hash)
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
