FROM alpine:3.21
RUN apk add --no-cache openssh-client
USER 65532:65532
ENTRYPOINT ["/bin/sh", "-c", "exec ssh -N -T -i /run/secrets/control-plane-tunnel-key -o IdentitiesOnly=yes -o UserKnownHostsFile=/run/secrets/sish-known-hosts -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -p \"$SSH_PORT\" -R \"$REMOTE_LABEL:80:127.0.0.1:8080\" \"$SSH_USER@$SSH_HOST\""]
