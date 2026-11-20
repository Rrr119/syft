FROM alpine:3.18.3@sha256:7144f7bab3d4c2648d7e59409f15ec52a18006a128c733fcff20d3a4a54ba44a AS base

# a package-manager-owned package that the in-house manifest will also (incorrectly) claim,
# to exercise cross-cataloger deduplication
RUN apk add --no-cache curl

# a first-party (in-house) build artifact deployed into the image, plus a manifest declaring it.
# The manifest is generated at build time so that the duplicate "curl" entry always matches
# the version of curl that apk actually installed.
RUN set -eux; \
    mkdir -p /opt/acme/bin; \
    printf '#!/bin/sh\necho acme-gateway\n' > /opt/acme/bin/gateway; \
    chmod +x /opt/acme/bin/gateway; \
    CURL_VERSION="$(apk info -v curl 2>/dev/null | sed -n 's/^curl-\(.*\)$/\1/p')"; \
    printf '{\n' \
           '  "version": 1,\n' \
           '  "artifacts": [\n' \
           '    {"name": "acme-gateway", "version": "2.3.1", "kind": "application", "supplier": "Acme Corp", "licenses": ["Proprietary"], "paths": ["/opt/acme/bin/gateway"]},\n' \
           '    {"name": "acme-sidecar", "version": "1.0.0", "kind": "library"},\n' \
           '    {"name": "acme-sidecar", "version": "1.0.0", "licenses": ["MIT"]},\n' \
           '    {"name": "curl", "version": "%s"}\n' \
           '  ]\n' \
           '}\n' "$CURL_VERSION" > /opt/acme/inhouse-manifest.json

# we only need the APK DB and the in-house artifacts, keep the image small
FROM scratch

COPY --from=base /lib/apk /lib/apk
COPY --from=base /opt/acme /opt/acme
