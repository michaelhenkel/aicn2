package cmd

import (
	"context"
	"fmt"
	"os"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/openshift/assisted-service/client/installer"
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
		client, err := api.NewClient(serviceURL, offlineToken)
		if err != nil {
			klog.Fatal(err)
		}
		clusterList, err := client.Installer.ListClusters(context.Background(), &installer.ListClustersParams{})
		if err != nil {
			klog.Fatal(err)
		}
		homedir, err := os.UserHomeDir()
		if err != nil {
			klog.Fatal(err)
		}
		for _, cl := range clusterList.GetPayload() {
			if cl.Name == args[0] {

				out, err := os.Create(fmt.Sprintf("%s/.aicn2/%s/config", homedir, cl.Name))
				if err != nil {
					klog.Fatal(err)
				}
				//downloads/files-presigned?file_name=kubeconfig-noingress
				defer out.Close()

				/*
					config := installer.NewDownloadClusterKubeconfigParams()
					config.SetClusterID(*cl.ID)

					if _, err = client.Installer.DownloadClusterKubeconfig(context.Background(), config, out); err != nil {
						klog.Fatal(err)
					}
				*/
				_, err = client.Installer.DownloadClusterFiles(context.Background(), &installer.DownloadClusterFilesParams{
					ClusterID: *cl.ID,
					FileName:  "kubeconfig-noingress",
				}, out)
				/*
					resp, err := client.Installer.GetPresignedForClusterFiles(context.Background(), &installer.GetPresignedForClusterFilesParams{
						ClusterID: *cl.ID,
						FileName:  "kubeconfig-noingress",
					})
				*/
				if err != nil {
					klog.Fatal(err)
				}
				//klog.Info(*resp.GetPayload().URL)
				/*
					httpResp, err := http.Get(*resp.GetPayload().URL)
					if err != nil {
						klog.Fatal(err)
					}
					if _, err := io.Copy(out, httpResp.Body); err != nil {
						klog.Fatal(err)
					}
				*/

			}
		}
	},
}
