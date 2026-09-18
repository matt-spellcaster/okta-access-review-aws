#!/bin/zsh
# Runs a live access review. Settings come from ./env; secrets are fetched
# from 1Password at startup and never written to disk.
# Any arguments are passed to access-review, e.g.:
#   ./run.sh --roster roster/dev-org-roster.csv --config roster/dev-org-config.json
set -e
DIR="${0:A:h}"
if [[ ! -r "$DIR/env" ]]; then
  echo "access-review: missing $DIR/env (copy env.example and fill it in)" >&2
  exit 1
fi
set -a; source "$DIR/env"; set +a

# read_secret NAME: print the secret that the 1Password reference in $NAME points to.
# Refuses anything that isn't an op:// reference *without echoing it*, because a
# secret pasted into a *_REF setting would otherwise show up in op's error message.
read_secret() {
  local ref="${(P)1}"
  if [[ "$ref" != op://* ]]; then
    echo "access-review: $1 in $DIR/env must be a 1Password reference (op://vault/item/field)," \
      "not the secret itself. If you pasted a real secret there, rotate it." >&2
    return 1
  fi
  if ! /opt/homebrew/bin/op read "$ref"; then
    echo "access-review: could not read $1 ($ref) from 1Password" >&2
    return 1
  fi
}

if [[ -z "$OKTA_PRIVATE_KEY_REF" ]]; then
  echo "access-review: OKTA_PRIVATE_KEY_REF is not set in $DIR/env" >&2
  exit 1
fi
OKTA_PRIVATE_KEY="$(read_secret OKTA_PRIVATE_KEY_REF)" || exit 1
export OKTA_PRIVATE_KEY

# Email is optional; only fetch the SMTP password when a recipient is set.
if [[ -n "$REPORT_EMAIL_TO" ]]; then
  if [[ -z "$SMTP_PASSWORD_REF" ]]; then
    echo "access-review: REPORT_EMAIL_TO is set but SMTP_PASSWORD_REF is not" >&2
    exit 1
  fi
  SMTP_PASSWORD="$(read_secret SMTP_PASSWORD_REF)" || exit 1
  export SMTP_PASSWORD
fi

# Slack is optional. Webhook URLs and bot tokens are secrets, so both live in 1Password.
if [[ -n "$SLACK_WEBHOOK_URL_REF" ]]; then
  SLACK_WEBHOOK_URL="$(read_secret SLACK_WEBHOOK_URL_REF)" || exit 1
  export SLACK_WEBHOOK_URL
fi
if [[ -n "$SLACK_BOT_TOKEN_REF" ]]; then
  SLACK_BOT_TOKEN="$(read_secret SLACK_BOT_TOKEN_REF)" || exit 1
  export SLACK_BOT_TOKEN
fi

unset OKTA_PRIVATE_KEY_REF SMTP_PASSWORD_REF SLACK_WEBHOOK_URL_REF SLACK_BOT_TOKEN_REF
cd "$DIR"
exec /opt/homebrew/bin/uv run --frozen access-review "$@"
