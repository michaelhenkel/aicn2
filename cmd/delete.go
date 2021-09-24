package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/cn2"
	"github.com/michaelhenkel/aicn2/pkg/infrastructure"
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
		workerCounter := 0
		controllerCounter := 0
		for _, cl := range clusterList {
			if cl.Name == args[0] {

				header := map[string]string{
					"accept":        "application/json",
					"Authorization": fmt.Sprintf("Bearer %s", token),
				}
				resp, err := utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v2/infra-envs//%s/hosts", assistedServiceAPI, cl.ID), "GET", header, nil, "")
				if err != nil {
					klog.Fatal(resp, err)
				}
				h := []api.Host{}
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					klog.Fatal(err)
				}
				if err := json.Unmarshal(body, &h); err != nil {
					klog.Fatal(err)
				}
				for _, host := range h {
					if host.Role == "master" {
						controllerCounter++
					}
					if host.Role == "worker" {
						workerCounter++
					}
				}

				header = map[string]string{
					"accept":        "application/json",
					"Authorization": fmt.Sprintf("Bearer %s", token),
				}
				resp, err = utils.HttpRequest(fmt.Sprintf("https://%s/api/assisted-install/v1/clusters/%s", assistedServiceAPI, cl.ID), "DELETE", header, nil, "")
				if err != nil {
					klog.Fatal(resp, err)
				}

			}
		}
		var infraInterface infrastructure.InfrastructureInterface
		c, err := cn2.New()
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
		homedir, err := os.UserHomeDir()
		if err != nil {
			klog.Fatal(err)
		}
		if err := infraInterface.DeleteStorage(infrastructure.Image{
			Name: args[0],
			Path: fmt.Sprintf("%s/.aicn2/%s.iso", homedir, cluster.Name),
		}, controllerCounter, workerCounter); err != nil {
			klog.Fatal(err)
		}
	},
}
