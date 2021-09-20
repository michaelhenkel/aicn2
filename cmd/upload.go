package cmd

import (
	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/spf13/cobra"
	"k8s.io/klog"
)

var (
	manifests string
)

func init() {
	upload.PersistentFlags().StringVarP(&manifests, "manifests", "m", "manifests", "manifests directory")
}

var upload = &cobra.Command{
	Use:   "upload",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			klog.Fatal("cluster name must be specified")
		}
		cluster, err := api.Get(args[0], token, assistedServiceAPI)
		if err != nil {
			klog.Fatal(err)
		}
		if err := cluster.Upload(manifests); err != nil {
			klog.Fatal(err)
		}
	},
}
