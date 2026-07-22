#!/usr/bin/env bash
set -euo pipefail

action="${1:-start}"
container_name="${PQ_PRIVATE_CONTAINER:-app-tron-pq-private}"
host_port="${PQ_PRIVATE_HTTP_PORT:-18090}"
data_dir="${PQ_PRIVATE_DATA_DIR:-${TMPDIR:-/tmp}/app-tron-pq-private-data}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

case "$(uname -m)" in
    arm64|aarch64)
        default_image="tronnile/java-tron@sha256:13160bb3ef00d0b631346e05f117afd48098d0e447e170b2284c2f0ec03a70b4"
        ;;
    *)
        default_image="tronnile/java-tron@sha256:6f610da5c22f9d687fe1f3fb8318e65cdd91633f5991d34ac8d79bc0df21ac0e"
        ;;
esac
image="${PQ_JAVA_TRON_IMAGE:-$default_image}"

case "$action" in
    start)
        mkdir -p "$data_dir"
        docker run -d \
            --name "$container_name" \
            -p "127.0.0.1:${host_port}:8090" \
            -v "$script_dir/config.conf:/java-tron/config-pq.conf:ro" \
            -v "$data_dir:/java-tron/data" \
            "$image" \
            -c /java-tron/config-pq.conf -d /java-tron/data -w
        ;;
    stop)
        docker stop "$container_name"
        docker rm "$container_name"
        ;;
    logs)
        docker logs -f "$container_name"
        ;;
    status)
        curl -fsS --retry 15 --retry-delay 1 --retry-connrefused \
            -X POST "http://127.0.0.1:${host_port}/wallet/getchainparameters" \
            -H "Content-Type: application/json" -d '{}'
        ;;
    *)
        echo "usage: $0 {start|stop|logs|status}" >&2
        exit 2
        ;;
esac
