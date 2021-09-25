package cmd

import (
	"github.com/spf13/cobra"
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

	},
}
