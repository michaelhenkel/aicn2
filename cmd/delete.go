package cmd

import (
	"context"
	"fmt"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/cn2"
	"github.com/michaelhenkel/aicn2/pkg/infrastructure"
	"github.com/michaelhenkel/aicn2/pkg/utils"
	"github.com/openshift/assisted-service/client/installer"
	"github.com/openshift/assisted-service/models"
	"github.com/spf13/cobra"
	"k8s.io/klog"
)

func init() {
	delete.PersistentFlags().IntVarP(&worker, "worker", "w", 0, "worker count")
	delete.PersistentFlags().IntVarP(&controller, "controller", "c", 0, "controller count")
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

		workerCounter := 0
		controllerCounter := 0
		var cluster *models.Cluster
		for _, cl := range clusterList.GetPayload() {
			if cl.Name == args[0] {
				cluster = cl
				hostList := cluster.Hosts
				for _, host := range hostList {
					if host.Role == "worker" {
						workerCounter++
					}
					if host.Role == "master" {
						controllerCounter++
					}
				}
				if _, err := client.Installer.DeregisterCluster(context.Background(), &installer.DeregisterClusterParams{
					ClusterID: *cluster.ID,
				}); err != nil {
					klog.Error(err)
				}
				if _, err := client.Installer.ResetCluster(context.Background(), &installer.ResetClusterParams{
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
		if worker != 0 {
			workerCounter = worker
		}
		if controller != 0 {
			controllerCounter = controller
		}
		var infraInterface infrastructure.InfrastructureInterface
		c, err := cn2.New()
		if err != nil {
			klog.Fatal(err)
		}
		infraInterface = c
		_, err = infraInterface.DeleteVMS(args[0], controllerCounter, workerCounter)
		if err != nil {
			klog.Fatal(err)
		}
		if err := infraInterface.DeleteDNSLB(args[0]); err != nil {
			klog.Fatal(err)
		}
		if err := infraInterface.DeleteVN(args[0]); err != nil {
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
