package poll

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"net/url"
	"time"
)

type ImageStatus struct {
	Image   string
	ImageID string
}

func (i ImageStatus) ImageSHA() string {
	imageParts, err := url.Parse(i.ImageID)
	if err != nil {
		return i.ImageID
	}
	return fmt.Sprintf("%s%s", imageParts.Host, imageParts.Path)
}

func Images(clientset *kubernetes.Clientset, interval time.Duration, images chan ImageStatus, ctx context.Context) error {
	ticker := time.NewTicker(interval)
	var list = func(clientset *kubernetes.Clientset, images chan ImageStatus, ctx context.Context) error {
		pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return err
		}
		for _, pod := range pods.Items {
			for _, containerStatus := range pod.Status.ContainerStatuses {
				images <- ImageStatus{
					Image:   containerStatus.Image,
					ImageID: containerStatus.ImageID,
				}
			}
		}
		return nil
	}
	if err := list(clientset, images, ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := list(clientset, images, ctx); err != nil {
				return err
			}
		}
	}
}
