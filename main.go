package main

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher-metadata/metadata"
	"github.com/rancher/network-policy-manager/policy"
	"github.com/urfave/cli"
)

// VERSION of the application, that can defined during build time
var VERSION = "v0.0.0-dev"

const (
	metadataURLTemplate = "http://%v/2016-07-29"
)

func main() {
	app := cli.NewApp()
	app.Name = "network-policy-manager"
	app.Version = VERSION
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "metadata-address",
			Value: "169.254.169.250",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Turn on debug logging",
		},
		cli.BoolFlag{
			Name:  "cleanup",
			Usage: "Cleanup everything related to policy when service is stoppped",
		},
	}
	app.Action = run
	app.Run(os.Args)
}

func run(c *cli.Context) error {
	if c.Bool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	metadataURL := fmt.Sprintf(metadataURLTemplate, c.String("metadata-address"))
	logrus.Infof("Waiting for metadata")
	mClient, err := metadata.NewClientAndWait(metadataURL)
	if err != nil {
		return errors.Wrap(err, "Creating metadata client")
	}

	exitCh := make(chan int)
	if err := policy.Watch(mClient, exitCh, c.Bool("cleanup")); err != nil {
		logrus.Errorf("Failed to start policy-manger: %v", err)
	}

	<-exitCh
	logrus.Infof("Program exiting")
	return nil
}
