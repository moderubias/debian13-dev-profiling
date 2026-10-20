#!/usr/bin/env bash
# Run from the repository root; do not mount host state into this container.
set -euo pipefail
qa_container="d13dp-systemd-qa-$$"
qa_image="$qa_container:local"
cleanup() {
    qa_result=$?
    if [ "$qa_result" -ne 0 ]; then
        docker logs --tail 80 "$qa_container" 2>/dev/null || true
        docker exec "$qa_container" journalctl -u d13dp-network.service --no-pager 2>/dev/null || true
    fi
    docker rm -f "$qa_container" >/dev/null 2>&1 || true
}
trap cleanup EXIT
build_args=()
if [ -n "${D13DP_BUILD_NETWORK:-}" ]; then
    build_args+=(--network "$D13DP_BUILD_NETWORK")
fi
docker build "${build_args[@]}" -t "$qa_image" -f tests/integration/Dockerfile.systemd .
docker run -d --name "$qa_container" --network none --cgroupns private --privileged \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$qa_image"
docker exec -e D13DP_ISOLATED_QA=1 "$qa_container" /opt/d13dp/bin/python /project/tests/integration/network_systemd.py
docker exec -e D13DP_ISOLATED_QA=1 "$qa_container" /opt/d13dp/bin/python /project/tests/integration/network_systemd.py --prepare-boot
docker restart --timeout 10 "$qa_container"
docker exec -e D13DP_ISOLATED_QA=1 "$qa_container" /opt/d13dp/bin/python /project/tests/integration/network_systemd.py --check-boot
