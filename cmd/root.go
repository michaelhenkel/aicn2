package cmd

import (
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/klog"
)

type method string

const (
	POST   method = "POST"
	GET    method = "GET"
	DELETE method = "DELETE"
)

var (
	assistedServiceAPI string
	offlineToken       string
	//token              string
	kubeconfigPath string
	internal       bool
	serviceURL     *url.URL
)

var rootCmd = &cobra.Command{
	Use: "aicn2",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&offlineToken, "offlinetoken", "", "access token file")
	rootCmd.PersistentFlags().StringVar(&assistedServiceAPI, "apiurl", "http://10.87.88.2/api/assisted-install", "api url")
	rootCmd.PersistentFlags().StringVarP(&kubeconfigPath, "kubeconfig", "k", "", "path to kubeconfig")
	rootCmd.PersistentFlags().BoolVarP(&internal, "internal", "i", false, "path to kubeconfig")
	rootCmd.AddCommand(create)
	rootCmd.AddCommand(delete)
	rootCmd.AddCommand(get)
	rootCmd.AddCommand(list)
	rootCmd.AddCommand(upload)
	rootCmd.AddCommand(getmanifests)
	rootCmd.AddCommand(kubeconfig)
}

func initConfig() {
	var err error
	serviceURL, err = url.Parse(assistedServiceAPI)
	if err != nil {
		klog.Fatal(err)
	}
}
