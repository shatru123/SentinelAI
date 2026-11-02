# Kubernetes deployment

The Phase 1 Compose deployment is the supported local runtime. Kubernetes manifests are intentionally kept as a deployment boundary until worker enrollment, mTLS, secret rotation, and the RabbitMQ transport adapter are enabled in later phases. Do not expose the worker directly to the public network.
