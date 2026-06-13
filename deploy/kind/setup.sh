#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="complytime-studio"
NAMESPACE="${NAMESPACE:-kagent}"

VERTEX_PROJECT_ID="${VERTEX_PROJECT_ID:-}"
VERTEX_LOCATION="${VERTEX_LOCATION:-us-east5}"
GCP_ADC_PATH="${GCP_ADC_PATH:-${HOME}/.config/gcloud/application_default_credentials.json}"

info()  { echo "==> $*"; }
warn()  { echo "WARNING: $*" >&2; }
fatal() { echo "ERROR: $*" >&2; exit 1; }

detect_container_runtime() {
    if podman info &>/dev/null 2>&1; then
        CONTAINER_RUNTIME="podman"
        export KIND_EXPERIMENTAL_PROVIDER=podman
        info "Detected podman — setting KIND_EXPERIMENTAL_PROVIDER=podman"
    elif docker info &>/dev/null 2>&1; then
        CONTAINER_RUNTIME="docker"
    else
        fatal "No container runtime found. Install docker or podman."
    fi
}

check_prerequisites() {
    local missing=()
    for cmd in kind kubectl helm; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        fatal "Missing required tools: ${missing[*]}"
    fi
}

create_cluster() {
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        info "Cluster '${CLUSTER_NAME}' already exists, skipping creation"
        kind export kubeconfig --name "${CLUSTER_NAME}"
        return
    fi
    info "Creating kind cluster '${CLUSTER_NAME}'..."
    kind create cluster --config "${SCRIPT_DIR}/cluster.yaml"
}

fix_coredns_for_podman() {
    if [[ "${CONTAINER_RUNTIME}" != "podman" ]]; then
        return
    fi

    info "Applying CoreDNS fix for podman (explicit upstream nameservers)..."

    # Get the host's real nameservers (outside the container).
    # The || true guards against pipefail when all entries are localhost stubs.
    local nameservers
    nameservers=$(grep -oP '(?<=nameserver\s)\S+' /etc/resolv.conf \
        | grep -v '127.0.0' \
        | head -2 \
        | tr '\n' ' ' || true)

    if [[ -z "${nameservers// /}" ]]; then
        nameservers="8.8.8.8 8.8.4.4"
        warn "Could not detect host nameservers, falling back to Google DNS"
    fi

    info "Using upstream nameservers: ${nameservers}"

    # Patch the Corefile in-place via kubectl patch (avoids last-applied-configuration warning)
    local current_corefile
    current_corefile=$(kubectl get configmap coredns -n kube-system \
        -o jsonpath='{.data.Corefile}')

    local patched_corefile
    # shellcheck disable=SC2001 # bash parameter expansion can't target mid-string patterns in multiline content
    patched_corefile=$(echo "$current_corefile" \
        | sed "s|forward \. /etc/resolv\.conf|forward . ${nameservers}|g")

    # Use JSON patch to update the single key
    kubectl patch configmap coredns -n kube-system --type merge \
        -p "{\"data\":{\"Corefile\":$(echo "$patched_corefile" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}}"

    # Force-delete existing CoreDNS pods so they restart immediately with the new config.
    # A rollout restart hangs when DNS is already broken (graceful shutdown can't complete).
    info "Force-restarting CoreDNS pods..."
    kubectl delete pods -n kube-system -l k8s-app=kube-dns --force --grace-period=0 2>/dev/null || true

    # Wait for new pods to come up
    local retries=0
    while [[ $retries -lt 30 ]]; do
        local ready
        ready=$(kubectl get deployment coredns -n kube-system \
            -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        if [[ "${ready:-0}" -ge 1 ]]; then
            info "CoreDNS is ready (${ready} replicas)"
            break
        fi
        sleep 2
        retries=$((retries + 1))
    done

    if [[ $retries -ge 30 ]]; then
        warn "CoreDNS did not become ready within 60s — continuing anyway"
    fi

    # Verify DNS works
    info "Verifying cluster DNS..."
    kubectl run studio-dns-test --image=busybox:1.36 --restart=Never \
        --overrides='{"spec":{"terminationGracePeriodSeconds":0}}' \
        -- sleep 30 2>/dev/null || true
    sleep 8

    if kubectl exec studio-dns-test -- nslookup kubernetes.default &>/dev/null; then
        info "DNS is working"
    else
        warn "DNS verification failed — cluster networking may be unreliable"
    fi
    kubectl delete pod studio-dns-test --force --grace-period=0 2>/dev/null || true
}

fix_node_dns_for_podman() {
    if [[ "${CONTAINER_RUNTIME}" != "podman" ]]; then
        return
    fi

    info "Patching Kind node DNS for containerd image pulls..."

    # Podman injects its own DNS gateway into the Kind node's /etc/resolv.conf.
    # That gateway can't resolve external registries, so containerd image pulls
    # fail with i/o timeout. Patch with real upstream nameservers from the host.
    local nameservers
    nameservers=$(resolvectl status 2>/dev/null \
        | grep -oP '(?<=DNS Servers:\s)\S+' \
        | grep -v ':' \
        | head -2 \
        | tr '\n' ' ' || true)

    if [[ -z "${nameservers// /}" ]]; then
        nameservers="8.8.8.8 8.8.4.4"
        warn "Could not detect host nameservers, falling back to Google DNS"
    fi

    local resolv_content=""
    for ns in $nameservers; do
        resolv_content="${resolv_content}nameserver ${ns}\n"
    done
    resolv_content="${resolv_content}nameserver 8.8.8.8"

    "${CONTAINER_RUNTIME}" exec "${CLUSTER_NAME}-control-plane" \
        sh -c "printf '${resolv_content}\n' > /etc/resolv.conf"
    "${CONTAINER_RUNTIME}" exec "${CLUSTER_NAME}-control-plane" \
        sh -c 'systemctl restart containerd'

    sleep 3
    info "Node DNS patched and containerd restarted"

    info "Verifying image pull capability..."
    if "${CONTAINER_RUNTIME}" exec "${CLUSTER_NAME}-control-plane" \
        crictl pull docker.io/library/busybox:1.36 2>/dev/null; then
        info "Image pull verified"
    else
        warn "Image pull test failed — pods may hit ImagePullBackOff"
    fi
}

validate_env() {
    if [[ -z "$VERTEX_PROJECT_ID" ]]; then
        fatal "VERTEX_PROJECT_ID is required. Export it before running this script."
    fi
    if [[ ! -f "$GCP_ADC_PATH" ]]; then
        fatal "GCP credentials not found at ${GCP_ADC_PATH}. Run: gcloud auth application-default login"
    fi
}

create_secrets() {
    info "Configuring secrets..."

    kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

    kubectl create secret generic studio-gcp-credentials \
        --namespace "${NAMESPACE}" \
        --from-file=application_default_credentials.json="${GCP_ADC_PATH}" \
        --dry-run=client -o yaml | kubectl apply -f -

    if [[ -n "${OIDC_CLIENT_SECRET:-}" ]]; then
        kubectl create secret generic studio-oauth-credentials \
            --namespace "${NAMESPACE}" \
            --from-literal=client-secret="${OIDC_CLIENT_SECRET}" \
            --dry-run=client -o yaml | kubectl apply -f -
        info "OIDC client secret written to studio-oauth-credentials"
    else
        warn "OIDC_CLIENT_SECRET not set — skipping studio-oauth-credentials. Set it before deploying if OIDC is configured."
    fi
}

wait_for_ready() {
    info "Kind cluster '${CLUSTER_NAME}' is ready."
}

install_kagent() {
    info "Installing kagent CRDs..."
    helm upgrade --install kagent-crds \
        oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
        --namespace "${NAMESPACE}" \
        --create-namespace \
        --version ">=0.8.0" \
        --wait \
        --timeout 3m

    info "Installing kagent..."
    helm upgrade --install kagent \
        oci://ghcr.io/kagent-dev/kagent/helm/kagent \
        --namespace "${NAMESPACE}" \
        --timeout 10m

    info "Waiting for kagent controller..."
    kubectl rollout status deployment/kagent-controller \
        --namespace "${NAMESPACE}" --timeout=180s 2>/dev/null || true
}

print_access() {
    info ""
    info "Cluster ready. Next steps:"
    info ""
    info "  Deploy Studio:   make deploy"
    info "  Port forward:    kubectl port-forward -n ${NAMESPACE} svc/studio-gateway 8080:8080"
    info "  Open:            http://localhost:8080"
    info ""
    info "  Tear down:       make cluster-down"
}

main() {
    info "Setting up ComplyTime Studio cluster infrastructure..."
    check_prerequisites
    validate_env
    detect_container_runtime
    create_cluster
    fix_coredns_for_podman
    fix_node_dns_for_podman
    install_kagent
    create_secrets
    wait_for_ready
    print_access
}

main "$@"
