# Run by the task's `config` container, in the nginx image, before nginx and byrle start. The
# release image has no shell, so this writes what byrle and nginx read onto the task's
# volumes:
#   /config/policy.yaml    byrle's policy, from BYRLE_POLICY_YAML
#   /nginx/byrle.conf      nginx.conf.template, with BYRLE_VPC_CIDR and BYRLE_RP_KEY filled in
#   /spool                 made 65532's, the release image's user
set -eu
umask 077
printf '%s\n' "$BYRLE_POLICY_YAML" >/config/policy.yaml
chown 65532:65532 /config/policy.yaml
printf '%s\n' "$BYRLE_NGINX_TEMPLATE" \
    | envsubst '${BYRLE_VPC_CIDR} ${BYRLE_RP_KEY}' >/nginx/byrle.conf
chown 65532:65532 /spool
