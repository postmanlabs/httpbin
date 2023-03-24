# httpbin with compact alpine container

The goal is:

- compact secure container based on alpine linux
- runnable in kubernetes / OpenShift / OKD in a secure and scalable fashion
- multi architecture container (at least linux/amd64 and linux/arm64: means modern Intel, modern raspis and modern Macs with Mx processor)

## build

We are building the containers with podman (podman-desktop under MacOS or Windows):

```shell
podman build --manifest quay.io/pflaeging/httpbin:0.9.2-alpine --rm --no-cache --platform linux/amd64 --platform linux/arm64 -f Dockerfile.alpine .
podman manifest push quay.io/pflaeging/httpbin:0.9.2-alpine docker://quay.io/pflaeging/httpbin:0.9.2-alpine --rm
```

 (please replace the `quay.io/pflaeging` part with your own registry place)

## Kubernetes rollout

The application is fully compatible with Kubernetes / OpenShift4 / OKD4.

Example objects are in the folder [./kubernetes/](./kubernetes/).
