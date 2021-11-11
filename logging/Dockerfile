FROM registry.access.redhat.com/ubi7/ubi-minimal:latest

RUN mkdir /ishield-app && mkdir -p /ishield-app/public

COPY build/_bin/ishield-logger /ishield-app/logger

RUN chgrp -R 0 /ishield-app && chmod -R g=u /ishield-app

WORKDIR /ishield-app

ENTRYPOINT ["/ishield-app/logger"]
