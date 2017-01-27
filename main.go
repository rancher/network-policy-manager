package main

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher-metadata/metadata"
	"github.com/rancher/network-policy-manager/policy"
	"github.com/urfave/cli"
)

// VERSION of the application, that can defined during build time
var VERSION = "v0.0.0-dev"

func main() {
	app := cli.NewApp()
	app.Name = "network-policy-manager"
	app.Version = VERSION
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "metadata-url",
			Value: "http://169.254.169.250/2016-07-29",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Turn on debug logging",
		},
	}
	app.Action = run
	app.Run(os.Args)
}

func run(c *cli.Context) error {
	if c.Bool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.Infof("Waiting for metadata")
	mClient, err := metadata.NewClientAndWait(c.String("metadata-url"))
	if err != nil {
		return errors.Wrap(err, "Creating metadata client")
	}

	exitCh := make(chan int)
	if err := policy.Watch(mClient, exitCh); err != nil {
		logrus.Errorf("Failed to start policy-manger: %v", err)
	}

	<-exitCh
	logrus.Infof("Program exiting")
	return nil
}
