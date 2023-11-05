package scan

import (
	"context"
	"github.com/owenrumney/go-sarif/sarif"
	"github.com/richardjennings/scand/poll"
	"log"
)

type DummyScanner struct {
}

func (n *DummyScanner) Scan(images chan poll.ImageStatus, ctx context.Context, result chan Result) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case imgStatus := <-images:
			log.Printf("proccessed dummy scan for %s", imgStatus.ImageSHA())
			result <- Result{
				ImageStatus: imgStatus,
				Report:      &sarif.Report{},
			}
		}
	}
}
