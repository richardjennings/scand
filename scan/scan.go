package scan

import (
	"context"
	"github.com/owenrumney/go-sarif/sarif"
	"github.com/richardjennings/scand/poll"
)

type Result struct {
	ImageStatus poll.ImageStatus
	Report      *sarif.Report
}

type Scanner interface {
	Scan(images chan poll.ImageStatus, ctx context.Context, result chan Result) error
}
