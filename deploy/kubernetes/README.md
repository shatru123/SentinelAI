# Kubernetes deployment

The Compose deployment is the supported local runtime. Kubernetes manifests are intentionally kept as a deployment boundary until worker enrollment hardening, mTLS, secret rotation, broker policies, egress policies, and a tested migration strategy are completed. Do not expose the worker directly to the public network.
