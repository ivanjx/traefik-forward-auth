# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/sdk:11.0.100-resolute-aot AS build
ARG TARGETARCH
WORKDIR /src

COPY . .

RUN case "$TARGETARCH" in \
        amd64) RID=linux-x64 ;; \
        arm64) RID=linux-arm64 ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && dotnet publish src/TraefikForwardAuth/TraefikForwardAuth.csproj \
        -c Release \
        -r "$RID" \
        -o /app/publish \
        -p:TreatWarningsAsErrors=true \
    && mkdir -p /app/data

FROM mcr.microsoft.com/dotnet/runtime-deps:11.0-resolute-chiseled
WORKDIR /app

COPY --from=build --chown=1654:1654 /app/publish/ ./
COPY --from=build --chown=1654:1654 /app/data /data

ENV DATA_DIR=/data

VOLUME /data
EXPOSE 4181 4182
USER 1654

ENTRYPOINT ["./traefik-forward-auth"]
