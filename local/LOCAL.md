

curl -X GET "https://quay.io/api/v1/repository/verygoodsecurity/httpbin/tag/?page=2" | jq

```json
{
  "name": "production-0.1.27",
  "reversion": false,
  "start_ts": 1598610088,
  "manifest_digest": "sha256:b37ccee7c2a645b3be17b360b7625fd1321ff528878431cb3e33008d7f512cc4",
  "is_manifest_list": false,
  "size": 167255693,
  "last_modified": "Fri, 28 Aug 2020 10:21:28 -0000"
}
```

```
#RUN apk --update add --no-cache \
#    g++=9.3.0 \
#    gcc=9.3.0 \
#    python3-dev=3.8.5 \
#    build-base=0.5 \
#    libffi-dev=3.3 \
#    musl-dev=1.1.24 \
#    git=2.26.2
```