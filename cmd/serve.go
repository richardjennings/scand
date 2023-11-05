package cmd

import (
	"context"
	"github.com/richardjennings/scand/poll"
	"github.com/richardjennings/scand/scan"
	"github.com/richardjennings/scand/status"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"time"
)

var kubeConfig string
var numScannerWorkers = 1
var rescanIntervalMinutes = 1
var scanner string
var cachePath string
var syftPath string
var grypePath string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the service",
	Run: func(cmd *cobra.Command, args []string) {
		if kubeConfig == "" {
			log.Fatalln("in cluster support not yet added")
		}
		if scanner == "" {
			log.Fatalln("scanner must be specified")
		}
		var s scan.Scanner
		var err error
		switch scanner {
		case "dummy":
			s = &scan.DummyScanner{}
		case "grype":
			s, err = scan.NewGrypeScanner(cachePath, syftPath, grypePath)
			if err != nil {
				log.Fatalln(err)
			}
		default:
			log.Fatalf("invalid scanner %s provided", scanner)
		}

		server := status.NewStatus()

		config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
		if err != nil {
			panic(err.Error())
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			panic(err.Error())
		}

		eg := errgroup.Group{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		images := make(chan poll.ImageStatus, 200)
		results := make(chan scan.Result, 200)

		eg.Go(func() error {
			return poll.Images(clientset, time.Minute*time.Duration(rescanIntervalMinutes), images, ctx)
		})

		for i := 0; i < numScannerWorkers; i++ {
			eg.Go(func() error {
				return s.Scan(images, ctx, results)
			})
		}

		eg.Go(func() error {
			return server.Handle()
		})

		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				case res := <-results:
					server.Update(res)
				}
			}
		})

		if err := eg.Wait(); err != nil {
			log.Println(err)
		}
	},
}

func init() {
	serveCmd.Flags().StringVarP(&kubeConfig, "kube-config", "k", "", "specify absolute kubeconfig file path")
	serveCmd.Flags().StringVarP(&scanner, "scanner", "s", "grype", "specify scanner")
	serveCmd.Flags().StringVar(&cachePath, "cache-path", "/tmp/scand", "path to cache directory")
	serveCmd.Flags().StringVar(&syftPath, "syft-path", "", "path to syft binary")
	serveCmd.Flags().StringVar(&grypePath, "grype-path", "", "path to syft binary")
	serveCmd.Flags().IntVar(&numScannerWorkers, "workers", 4, "number of scanner workers")
	serveCmd.Flags().IntVar(&rescanIntervalMinutes, "rescan-interval", 10, "rescan interval in minutes")
	rootCmd.AddCommand(serveCmd)
}
