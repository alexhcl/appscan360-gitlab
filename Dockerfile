# Runner image for the HCL AppScan 360° GitLab integration (Python edition).
# Pre-installs Python + requests, the SAClientUtil downloaded from YOUR 360° instance
# (cloud builds are not compatible), a JDK, Maven/Gradle (Java IRX generation) and Docker CLI
# (SCA of images). The integration scripts are baked in at /opt/appscan360 so jobs can use
# APPSCAN_SCRIPTS_SOURCE=runner APPSCAN_SCRIPTS_DIR=/opt/appscan360.
#
#   docker build -t appscan360-runner \
#     --build-arg APPSCAN_SERVICE_URL=https://appscan360.example.com \
#     --build-arg ACCEPT_UNTRUSTED_SSL=yes .
FROM ubuntu:24.04
ARG APPSCAN_SERVICE_URL
ARG ACCEPT_UNTRUSTED_SSL=yes
ENV DEBIAN_FRONTEND=noninteractive HOME=/root APPSCAN_INSTALL_DIR=/opt/SAClientUtil \
    PATH="/opt/SAClientUtil/bin:${PATH}"
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-requests curl unzip git ca-certificates \
      openjdk-17-jdk maven gradle docker.io && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN test -n "$APPSCAN_SERVICE_URL" || (echo "Set --build-arg APPSCAN_SERVICE_URL" && exit 1) && \
    SSL=""; [ "$ACCEPT_UNTRUSTED_SSL" = "yes" ] && SSL="-k"; \
    host="${APPSCAN_SERVICE_URL%/}"; case "$host" in http*) ;; *) host="https://$host";; esac; \
    curl $SSL -sSf "$host/api/v4/Tools/SAClientUtilByType?toolType=linux" -o /tmp/sa.zip && \
    unzip -q /tmp/sa.zip -d /tmp/sa && mv /tmp/sa/SAClientUtil* /opt/SAClientUtil && rm -rf /tmp/sa /tmp/sa.zip && \
    appscan.sh version || true
COPY appscan360.py requirements.txt /opt/appscan360/
COPY as360 /opt/appscan360/as360
ENV APPSCAN_SCRIPTS_SOURCE=runner APPSCAN_SCRIPTS_DIR=/opt/appscan360
