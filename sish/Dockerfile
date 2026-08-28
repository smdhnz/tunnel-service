FROM golang:1.26-bookworm AS build
ARG SISH_COMMIT=9609e83bb87aa7c65b14a67e84738c9ad13cd3ca
WORKDIR /src
RUN git clone https://github.com/antoniomika/sish.git . \
 && git checkout --detach "${SISH_COMMIT}" \
 && test "$(git rev-parse HEAD)" = "${SISH_COMMIT}"
COPY patches/control-plane.patch /tmp/control-plane.patch
RUN git apply --recount --check /tmp/control-plane.patch \
 && git apply --recount /tmp/control-plane.patch \
 && go test ./utils ./sshmuxer ./httpmuxer \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/antoniomika/sish/cmd.Commit=${SISH_COMMIT}" -o /out/sish .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sish /sish
COPY --from=build /src/templates /templates
ENTRYPOINT ["/sish"]
