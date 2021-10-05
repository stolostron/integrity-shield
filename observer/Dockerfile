FROM registry.access.redhat.com/ubi7/ubi-minimal:7.9

RUN mkdir /ishield-app && mkdir /ishield-app/resources

COPY build/_bin/ishield-observer /ishield-app/observer

RUN chgrp -R 0 /ishield-app && chmod -R g=u /ishield-app

WORKDIR /ishield-app

ENTRYPOINT ["/ishield-app/observer"]
