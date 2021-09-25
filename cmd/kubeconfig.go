package cmd

import (
	"github.com/spf13/cobra"
)

var ()

func init() {

}

var kubeconfig = &cobra.Command{
	Use:   "kubeconfig",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

	},
}
