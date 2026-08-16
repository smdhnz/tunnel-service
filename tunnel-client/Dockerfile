FROM alpine:3.21
ARG TUNNEL_UID=1000
ARG TUNNEL_GID=1000
RUN apk add --no-cache openssh-client \
 && addgroup -g "$TUNNEL_GID" tunnel \
 && adduser -D -u "$TUNNEL_UID" -G tunnel tunnel
USER tunnel:tunnel
ENTRYPOINT ["/bin/sh", "-c", "exec ssh -N -T -i /run/secrets/control-plane-tunnel-key -o IdentitiesOnly=yes -o UserKnownHostsFile=/run/secrets/sish-known-hosts -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -p \"$SSH_PORT\" -R \"$REMOTE_LABEL:80:127.0.0.1:8080\" \"$SSH_USER@$SSH_HOST\""]
