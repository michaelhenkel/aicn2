package cmd

import (
	"fmt"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/utils"
	"github.com/spf13/cobra"
	"k8s.io/klog"
)

var delete = &cobra.Command{
	Use:   "delete [name]",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			klog.Fatal("name is missing")
		}
		cluster := api.NewCluster(token, assistedServiceAPI)
		clusterList, err := cluster.List()
		if err != nil {
			klog.Fatal(err)
		}
		for _, cl := range clusterList {
			if cl.Name == args[0] {
				header := map[string]string{
					"accept":        "application/json",
					"Authorization": fmt.Sprintf("Bearer %s", token),
				}
				_, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters/%s", assistedServiceAPI, cl.ID), "DELETE", header, nil, "")
				if err != nil {
					klog.Fatal(err)
				}
			}
		}
	},
}
