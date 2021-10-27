package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/openshift/assisted-service/client/installer"
	"github.com/openshift/assisted-service/models"
	"github.com/spf13/cobra"
	"k8s.io/klog"
)

var get = &cobra.Command{
	Use:   "get [name]",
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
		unregisteredClusters := false
		clusterList, err := client.Installer.ListClusters(context.Background(), &installer.ListClustersParams{
			GetUnregisteredClusters: &unregisteredClusters,
		})
		if err != nil {
			klog.Fatal(err)
		}

		var cluster *models.Cluster
		for _, cl := range clusterList.GetPayload() {
			klog.Info(cl.Name)
			if cl.Name == args[0] {
				cluster = cl
			}
		}
		if cluster != nil {
			clusterByte, err := json.Marshal(cluster)
			if err != nil {
				klog.Fatal(err)
			}
			fmt.Println(string(clusterByte))
		}
	},
}
