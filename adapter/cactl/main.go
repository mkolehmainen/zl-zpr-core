package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"zpr.org/cactl/ipc"

	"github.com/labstack/gommon/color"
	"github.com/urfave/cli/v2"
)

const VERSION = "0.0.1-beta"

const CD_CONTROL_SOCKET = "/var/run/zpr/cd.sock"

func main() {
	app := &cli.App{
		Name:    "cactl",
		Usage:   "ZPR client adapter control",
		Version: VERSION,
		Commands: []*cli.Command{
			connectCmd(),
			statusCmd(),
			disconnectCmd(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(color.Red(err.Error()))
		os.Exit(0)
	}
}

func connectCmd() *cli.Command {
	return &cli.Command{
		Name:  "connect",
		Usage: "Connect to a ZPR network",
		Action: func(c *cli.Context) error {
			configName := c.Args().Get(0)
			if configName == "" {
				return errors.New("missing configuration name")
			}
			cpath, err := filepath.Abs(configName)
			if err != nil {
				fmt.Print(color.Red("failed to parse configuration path"))
				fmt.Println("  {}", err)
			} else {
				ctl, err := ipc.NewCDCtl(CD_CONTROL_SOCKET)
				if err != nil {
					return err
				}
				result, err := ctl.Connect(cpath)
				if err != nil {
					return err
				}
				if result.IsError {
					fmt.Println(color.Red(result.Message()))
				} else {
					fmt.Println(color.Green(result.Message()))
				}
			}
			return nil
		},
	}
}

func statusCmd() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "Show status of active ZPR connections",
		Action: func(c *cli.Context) error {
			ctl, err := ipc.NewCDCtl(CD_CONTROL_SOCKET)
			if err != nil {
				return err
			}
			result, err := ctl.Status()
			if err != nil {
				return err
			}
			if result.IsError {
				fmt.Println(color.Red(result.Message()))
			} else {
				fmt.Println(color.Green(result.Message()))
			}
			return nil
		},
	}
}

func disconnectCmd() *cli.Command {
	return &cli.Command{
		Name:  "disconnect",
		Usage: "Disconnect from ZPR networks",
		Action: func(c *cli.Context) error {
			fmt.Print(color.Green("disconnecting all"))
			fmt.Println(color.Red(" -- not implemented"))
			return nil
		},
	}
}
