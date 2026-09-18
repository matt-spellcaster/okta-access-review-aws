#!/usr/bin/env bash
# Install the pinned Terraform (and, on amd64, TFLint) into $RUNNER_TEMP/bin, checking
# each download against a pinned SHA-256. Versions and checksums come from the
# workflow's env block. Usage: scripts/ci/install_terraform.sh amd64|arm64
set -euo pipefail
arch="${1:?usage: install_terraform.sh amd64|arm64}"
bin="${RUNNER_TEMP:?}/bin"
mkdir -p "$bin"
cd "$RUNNER_TEMP"

case "$arch" in
  amd64) tf_sha="$TERRAFORM_SHA256_AMD64" ;;
  arm64) tf_sha="$TERRAFORM_SHA256_ARM64" ;;
  *) echo "unknown arch $arch" >&2; exit 2 ;;
esac
zip="terraform_${TERRAFORM_VERSION}_linux_${arch}.zip"
curl -sSfL -o "$zip" "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/${zip}"
echo "${tf_sha}  ${zip}" | sha256sum --check --strict
unzip -oq "$zip" terraform -d "$bin"

if [ "$arch" = amd64 ]; then
  curl -sSfL -o tflint.zip \
    "https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_amd64.zip"
  echo "${TFLINT_SHA256}  tflint.zip" | sha256sum --check --strict
  unzip -oq tflint.zip tflint -d "$bin"
fi

echo "$bin" >> "$GITHUB_PATH"
