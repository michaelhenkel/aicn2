package cmd

import (
	"github.com/spf13/cobra"
)

var list = &cobra.Command{
	Use:   "list",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
	},
}
