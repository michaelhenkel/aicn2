package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/klog"

	api "github.com/michaelhenkel/aicn2/pkg/apis"
)

type method string

const (
	assistedServiceAPI        = "api.openshift.com"
	POST               method = "POST"
	GET                method = "GET"
	DELETE             method = "DELETE"
)

var (
	offlineToken string
	token        string
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
	rootCmd.AddCommand(create)
	rootCmd.AddCommand(delete)
	rootCmd.AddCommand(get)
	rootCmd.AddCommand(list)
	rootCmd.AddCommand(upload)
	rootCmd.AddCommand(getmanifests)
	rootCmd.AddCommand(kubeconfig)
}

func initConfig() {
	if offlineToken == "" {
		offlineToken = os.Getenv("OFFLINE_TOKEN")
		if offlineToken == "" {
			homedir, err := os.UserHomeDir()
			if err != nil {
				klog.Fatal(err)
			}
			offlineTokenByte, err := os.ReadFile(fmt.Sprintf("%s/.aicn2/.offlinetoken", homedir))
			if err != nil {
				klog.Fatal(fmt.Errorf("cannot access offline token"))
			}
			offlineToken = strings.TrimRight(string(offlineTokenByte), "\n")
		}
	}
	var err error
	token, err = api.GetToken(offlineToken)
	if err != nil {
		klog.Fatal("--offlinetoken must be provided or ACCESS_TOKEN env set or available in .offlinetoken ", err)
	}
}
