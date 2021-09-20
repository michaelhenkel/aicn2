package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/klog"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
)

var list = &cobra.Command{
	Use:   "list",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cluster := api.NewCluster(token, assistedServiceAPI)
		clusterList, err := cluster.List()
		if err != nil {
			klog.Fatal(err)
		}
		for _, cl := range clusterList {
			fmt.Printf("%+v", cl)
		}
	},
}
