package cmd

import (
	"context"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/cn2"
	"github.com/michaelhenkel/aicn2/pkg/infrastructure"
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

		client, err := api.NewClient(serviceURL, offlineToken)
		if err != nil {
			klog.Fatal(err)
		}
		infraEnvList, err := client.Installer.ListInfraEnvs(context.Background(), &installer.ListInfraEnvsParams{})
		if err != nil {
			klog.Fatal(err)
		}
		for _, infraEnv := range infraEnvList.GetPayload() {
			if infraEnv.Name != nil && *infraEnv.Name == args[0] {
				if _, err := client.Installer.V2DeregisterCluster(context.Background(), &installer.V2DeregisterClusterParams{
					ClusterID: infraEnv.ClusterID,
				}); err != nil {
					klog.Info(err)
				}
				if _, err := client.Installer.DeregisterInfraEnv(context.Background(), &installer.DeregisterInfraEnvParams{
					InfraEnvID: *infraEnv.ID}); err != nil {
					klog.Fatal(err)
				}
			}
		}

		clusterList, err := client.Installer.V2ListClusters(context.Background(), &installer.V2ListClustersParams{})
		if err != nil {
			klog.Fatal(err)
		}
		for _, cl := range clusterList.GetPayload() {
			if cl.Name == args[0] {

				if _, err := client.Installer.V2ResetCluster(context.Background(), &installer.V2ResetClusterParams{
					ClusterID: *cl.ID,
				}); err != nil {
					klog.Error(err)
				}

				if _, err := client.Installer.V2DeregisterCluster(context.Background(), &installer.V2DeregisterClusterParams{
					ClusterID: *cl.ID,
				}); err != nil {
					klog.Error(err)
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
	},
}
