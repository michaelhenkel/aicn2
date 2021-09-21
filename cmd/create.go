package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/klog"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/cn2"
	"github.com/michaelhenkel/aicn2/pkg/infrastructure"
)

var (
	file  string
	noiso bool
)

func init() {
	create.PersistentFlags().StringVar(&file, "file", "", "access token file")
	create.PersistentFlags().BoolVar(&noiso, "noiso", false, "don't create iso")
}

var create = &cobra.Command{
	Use:   "create [name]",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cluster := api.NewCluster(token, assistedServiceAPI)
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
		homedir, err := os.UserHomeDir()
		if err != nil {
			klog.Fatal(err)
		}
		if cluster.PullSecret == "" {
			pullSecretByte, err := os.ReadFile(fmt.Sprintf("%s/.aicn2/pull-secret.txt", homedir))
			if err != nil {
				klog.Fatal(err)
			}
			cluster.PullSecret = string(pullSecretByte)
		}
		if cluster.SSHPublicKey == "" {

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
		for _, cl := range clusterList {
			if cl.Name == cluster.Name {
				klog.Fatal("cluster already exists")
			}
		}
		if err := cluster.CreateCluster(); err != nil {
			klog.Fatal(err)
		}
		if err := cluster.GenerateISO(); err != nil {
			klog.Fatal(err)
		}
		if err := cluster.DownloadISO(); err != nil {
			klog.Fatal(err)
		}

		var infraInterface infrastructure.InfrastructureInterface
		c := &cn2.CN2{}
		infraInterface = c
		if err := infraInterface.PrepareStorage(infrastructure.Image{
			Name: cluster.Name,
			Path: fmt.Sprintf("%s/.aicn2/%s.iso", homedir, cluster.Name),
		}); err != nil {
			klog.Fatal(err)
		}

		if err := cluster.Upload("manifests"); err != nil {
			klog.Fatal(err)
		}
	},
}
