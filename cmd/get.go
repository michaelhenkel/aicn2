package cmd

import (
	"encoding/json"
	"fmt"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
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
		cluster, err := api.Get(args[0], token, assistedServiceAPI)
		if err != nil {
			klog.Fatal(err)
		}
		clusterByte, err := json.Marshal(cluster)
		if err != nil {
			klog.Fatal(err)
		}
		fmt.Println(string(clusterByte))
	},
}
