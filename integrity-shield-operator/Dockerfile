FROM registry.access.redhat.com/ubi7/ubi-minimal:7.9

RUN mkdir /ishield-op-app && \
    curl -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -o jq-linux64 && \
    chmod +x jq-linux64 && \
    mv jq-linux64 /usr/local/bin/jq


COPY build/_output/bin/integrity-shield-operator /ishield-op-app/manager
ADD bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml /ishield-op-app/bundle/manifests/integrity-shield-operator.clusterserviceversion.yaml

RUN chgrp -R 0 /ishield-op-app && chmod -R g=u /ishield-op-app

WORKDIR /ishield-op-app

ENTRYPOINT ["/ishield-op-app/manager"]
