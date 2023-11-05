# ScanD

## About
ScanD runs a Container Image Security Vulnerability scan against all images running in a cluster and exposes the results 
as a prometheus guage metric.

/metrics example:
```
scand_result{id="CVE-2023-4911-libc6",image="registry.k8s.io/kube-proxy@sha256:4bcb707da9898d2625f5d4edc6d0c96519a24f16db914fc673aa8f97e41dbabf",security_severity="7.8"} 0
scand_result{id="GHSA-2wrh-6pvc-2jm9-golang.org/x/net",image="gcr.io/k8s-minikube/storage-provisioner@sha256:18eb69d1418e854ad5a19e399310e52808a8321e4c441c1dddad8977a0d7a944",security_severity="6.1"} 0
scand_result{id="GHSA-2wrh-6pvc-2jm9-golang.org/x/net",image="registry.k8s.io/coredns/coredns@sha256:a0ead06651cf580044aeb0a0feba63591858fb2e43ade8c9dea45a6a89ae7e5e",security_severity="6.1"} 0
```

By default ScanD uses Syft and Grype.

Syft is used to generate an Software Bill of Materials (SBOM) which is cached.

Grype is configured to scan the cached SBOM for security vulnerabilities. 

## Usage

```
go run main.go serve -k /Users/test/.kube/config --syft-path /opt/homebrew/bin/syft --grype-path /opt/homebrew/bin/grype
```

## Status

Proof of concept development.