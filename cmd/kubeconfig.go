package cmd

import (
	"fmt"
	"io"
	"os"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/utils"
	"github.com/spf13/cobra"
	"k8s.io/klog"
)

var ()

func init() {

}

var kubeconfig = &cobra.Command{
	Use:   "kubeconfig",
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
					"Content-Type":  "application/json",
					"Authorization": fmt.Sprintf("Bearer %s", token),
				}
				resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters/%s/downloads/kubeconfig", assistedServiceAPI, cl.ID), "GET", header, nil, "")
				if err != nil {
					klog.Fatal(resp, err)
				}
				defer resp.Body.Close()
				// Create the file
				homedir, err := os.UserHomeDir()
				if err != nil {
					klog.Fatal(err)
				}
				out, err := os.Create(fmt.Sprintf("%s/.aicn2/%s-kubeconfig", homedir, cl.Name))
				if err != nil {
					klog.Fatal(err)
				}
				defer out.Close()

				// Write the body to file
				_, err = io.Copy(out, resp.Body)
				if err != nil {
					klog.Fatal(err)
				}
			}
		}
	},
}
