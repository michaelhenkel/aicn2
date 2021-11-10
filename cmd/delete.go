package cmd

import (
	"context"
	"fmt"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/cn2"
	"github.com/michaelhenkel/aicn2/pkg/infrastructure"
	"github.com/michaelhenkel/aicn2/pkg/utils"
	"github.com/openshift/assisted-service/client/installer"
	"github.com/spf13/cobra"
	"k8s.io/klog"
)

func init() {
	delete.PersistentFlags().StringVarP(&registry, "registry", "r", "registry.default.svc.cluster1.local:5000", "container registry for ISO")
}

var delete = &cobra.Command{
	Use:   "delete [name]",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			klog.Fatal("name is missing")
		}

		client, err := api.NewClient(token)
		if err != nil {
			klog.Fatal(err)
		}
		clusterList, err := client.Installer.ListClusters(context.Background(), &installer.ListClustersParams{})
		if err != nil {
			klog.Fatal(err)
		}
		for _, cl := range clusterList.GetPayload() {
			if cl.Name == args[0] {

				if _, err := client.Installer.ResetCluster(context.Background(), &installer.ResetClusterParams{
					ClusterID: *cl.ID,
				}); err != nil {
					klog.Error(err)
				}

				if _, err := client.Installer.DeregisterCluster(context.Background(), &installer.DeregisterClusterParams{
					ClusterID: *cl.ID,
				}); err != nil {
					klog.Error(err)
				}

				header := map[string]string{
					"accept":        "application/json",
					"Authorization": fmt.Sprintf("Bearer %s", token),
				}
				resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters/%s", assistedServiceAPI, cl.ID), "DELETE", header, nil, "")
				if err != nil {
					klog.Error(resp, err)
				}
			}
		}
		var infraInterface infrastructure.InfrastructureInterface
		c, err := cn2.New(registry, kubeconfigPath)
		if err != nil {
			klog.Fatal(err)
		}
		infraInterface = c
		if err := infraInterface.DeleteVMS(args[0]); err != nil {
			klog.Fatal(err)
		}
		if err := infraInterface.DeleteDNSLB(args[0]); err != nil {
			klog.Fatal(err)
		}
		if err := infraInterface.DeleteVN(args[0]); err != nil {
			klog.Fatal(err)
		}
		if err := infraInterface.DeleteAPIVip(args[0], "api"); err != nil {
			klog.Fatal(err)
		}
		if err := infraInterface.DeleteAPIVip(args[0], "ingress"); err != nil {
			klog.Fatal(err)
		}
		/*
			homedir, err := os.UserHomeDir()
			if err != nil {
				klog.Fatal(err)
			}

			if err := infraInterface.DeleteStorage(infrastructure.Image{
				Name: args[0],
				Path: fmt.Sprintf("%s/.aicn2/%s/disk.img", homedir, args[0]),
			}, controllerCounter, workerCounter, hostList); err != nil {
				klog.Fatal(err)
			}
		*/
	},
}
