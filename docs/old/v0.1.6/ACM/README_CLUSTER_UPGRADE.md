
# Upgrade OCP Cluster while Integrity Shield is running

OpenShift Container Platform (OCP) has a cluster upgrade function for an existing OCP cluster, and cluster admins can upgrade their clusters even while Integrity Shield is running.

However, during this upgrade, Kubernetes components such as pods, Kubernetes API server and some others will be unavailable for a while.

So this could make Integrity Shield protection unavailable just for a certain amount of time (a few minutes normally). For details of this limitation, please refer to [this](../README_LIMITATION.md).

Therefore, please note that signature protection would be disabled temporally during OCP cluster upgrade.
