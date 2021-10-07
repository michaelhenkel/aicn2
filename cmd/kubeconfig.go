package cmd

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
	"github.com/michaelhenkel/aicn2/pkg/cn2"
	"github.com/openshift/assisted-service/client/installer"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		client, err := api.NewClient(token)
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
				resp, err := client.Installer.GetPresignedForClusterFiles(context.Background(), &installer.GetPresignedForClusterFilesParams{
					ClusterID: *cl.ID,
					FileName:  "kubeconfig-noingress",
				})
				if err != nil {
					klog.Fatal(err)
				}
				//klog.Info(*resp.GetPayload().URL)
				httpResp, err := http.Get(*resp.GetPayload().URL)
				if err != nil {
					klog.Fatal(err)
				}
				if _, err := io.Copy(out, httpResp.Body); err != nil {
					klog.Fatal(err)
				}
				/*
					if _, err := client.Installer.DownloadClusterKubeconfig(context.Background(), &installer.DownloadClusterKubeconfigParams{
						ClusterID: *cl.ID,
					}, out); err != nil {
						klog.Fatal(err)
					}
				*/
			}
		}
		c, err := cn2.New(registry, kubeconfigPath)
		if err != nil {
			klog.Fatal(err)
		}
		nodeList, err := c.Client.K8S.CoreV1().Nodes().List(context.Background(), v1.ListOptions{
			LabelSelector: "node-role.kubernetes.io/master=",
		})
		if err != nil {
			klog.Fatal(err)
		}
		var masterIP string
		for _, node := range nodeList.Items {
			masterIP = node.Status.Addresses[0].Address
		}
		var np int32
		npSvc, err := c.Client.K8S.CoreV1().Services(args[0]).Get(context.Background(), "api-nodeport", v1.GetOptions{})
		if err != nil {
			klog.Fatal(err)
		}
		for _, port := range npSvc.Spec.Ports {
			if port.Port == 6443 {
				np = port.NodePort
			}
		}
		f, err := ioutil.ReadFile(fmt.Sprintf("%s/.aicn2/%s/config", homedir, args[0]))
		if err != nil {
			klog.Fatal(err)
		}
		r := bytes.NewReader(f)
		scanner := bufio.NewScanner(r)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			klog.Fatal(err)
		}
		reg, err := regexp.Compile(`    server: https://(.*):6443`)
		if err != nil {
			klog.Fatal(err)
		}
		var lineIdx *int
		var master string
		for idx, line := range lines {
			submatch := reg.FindStringSubmatch(line)
			if len(submatch) > 0 {
				lineIdx = &idx
				master = submatch[1]
				break
			}
		}
		if lineIdx != nil {
			lines[*lineIdx] = fmt.Sprintf("    server: https://%s:%d", master, np)
		}
		var newKubeconfig string
		for idx, line := range lines {
			if idx == 0 {
				newKubeconfig = line
			} else {
				newKubeconfig = fmt.Sprintf("%s\n%s", newKubeconfig, line)
			}
		}
		if err := ioutil.WriteFile(fmt.Sprintf("%s/.aicn2/%s/config", homedir, args[0]), []byte(newKubeconfig), 0660); err != nil {
			klog.Fatal(err)
		}
		fmt.Printf("export KUBECONFIG=%s/.aicn2/%s/config\n", homedir, args[0])
		fmt.Printf("add \"%s %s\" to /etc/hosts\n", masterIP, master)

	},
}
