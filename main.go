package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	// "log"
	cmds "github.com/anonymoussubmission001/origo/commands"
)

func newVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of origo cmd toolkit.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("*** proco ***: version 0.1")
		},
	}

	return cmd
}

func OrigoCommand() *cobra.Command {

	// create new cobra command
	cmd := &cobra.Command{
		Use:   "origo",
		Short: "\nWelcome,\n\nHERMES is a command-line tool to execute different stages of the origo codebase.\n",
	}

	// proco version command
	cmd.AddCommand(newVersionCommand())

	// proco proxy commands
	cmd.AddCommand(cmds.StartProxyCommand())
	cmd.AddCommand(cmds.StopProxyCommand())
	cmd.AddCommand(cmds.AliveProxyCommand())

	cmd.AddCommand(cmds.ProxyPostProcessCommand())
	cmd.AddCommand(cmds.ProxyVerifyCommand())

	return cmd
}

func main() {

	// start command-line toolkit
	cmd := OrigoCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(0)
	}
}
