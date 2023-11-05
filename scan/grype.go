package scan

import (
	"context"
	"errors"
	"fmt"
	"github.com/owenrumney/go-sarif/sarif"
	"github.com/richardjennings/scand/poll"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type GrypeScanner struct {
	CachePath string
	GrypePath string
	SyftPath  string
}

func (s *GrypeScanner) Scan(images chan poll.ImageStatus, ctx context.Context, result chan Result) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case imgStatus := <-images:
			image := imgStatus.ImageSHA()

			// if there is a sbom.json matching image already, no need to regenerate
			cacheKey := strings.Replace(image, "/", "-", -1)

			cache := filepath.Join(s.CachePath, cacheKey)

			if _, err := os.Stat(cache); err != nil {
				// generate sbom
				cmd := exec.Command(s.SyftPath, image, "--output", "syft-json", "--file", cache)
				cmd.Env = []string{
					fmt.Sprintf("GRYPE_DB_CACHE_DIR=%s", s.CachePath),
					"GRYPE_DB_AUTO_UPDATE=false",
				}
				if err := cmd.Start(); err != nil {
					log.Printf("error starting syft, %s", err)
					continue
				}
				if err := cmd.Wait(); err != nil {
					log.Printf("sbom generation failed for %s", image)
					continue
				}
				log.Printf("generated sbom for %s", image)
			}

			// scan
			sbom := fmt.Sprintf("sbom:%s", cache)
			reportCache := fmt.Sprintf("%s.sarif", cache)

			cmd := exec.Command(s.GrypePath, sbom, "--output", "sarif", "--file", reportCache)
			if err := cmd.Start(); err != nil {
				log.Printf("error starting grype, %s", err)
				continue
			}
			if err := cmd.Wait(); err != nil {
				log.Printf("scan failed for %s", sbom)
				continue
			}

			f, err := os.Open(reportCache)
			if err != nil {
				log.Printf("could not find sarif %s", reportCache)
				continue
			}
			out, err := io.ReadAll(f)
			if err := f.Close(); err != nil {
				log.Println(err)
				continue
			}
			if err != nil {
				log.Println(err)
				continue
			}
			report, err := sarif.FromBytes(out)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Printf("generated scan report for %s", image)
			result <- Result{
				ImageStatus: imgStatus,
				Report:      report,
			}
		}
	}
}

func NewGrypeScanner(cachePath string, syftPath string, grypePath string) (Scanner, error) {
	if syftPath == "" {
		return nil, errors.New("syft path not provided")
	}
	if grypePath == "" {
		return nil, errors.New("grype path not provided")
	}
	if _, err := os.Stat(syftPath); err != nil {
		return nil, fmt.Errorf("syft not found at %s", syftPath)
	}
	if _, err := os.Stat(grypePath); err != nil {
		return nil, fmt.Errorf("grype not found at %s", grypePath)
	}
	if _, err := os.Stat(cachePath); err != nil {
		if err := os.MkdirAll(cachePath, 0755); err != nil {
			return nil, err
		}
	}

	s := &GrypeScanner{
		CachePath: cachePath,
		GrypePath: grypePath,
		SyftPath:  syftPath,
	}
	// run db update
	err := s.UpdateDB()
	if err != nil {
		return nil, err
	}
	// @todo add ticker for periodic update
	return s, nil
}

func (s *GrypeScanner) UpdateDB() error {
	log.Printf("updating grype database")
	cmd := exec.Command(s.GrypePath, "db", "update")
	cmd.Env = []string{
		fmt.Sprintf("GRYPE_DB_CACHE_DIR=%s", s.CachePath),
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	log.Println("updated grype db")
	return nil
}
