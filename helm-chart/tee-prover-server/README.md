# tee-prover-server

![Version: 0.0.1](https://img.shields.io/badge/Version-0.0.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.0.1](https://img.shields.io/badge/AppVersion-v0.0.1-informational?style=flat-square)

The prover server allows a seamless interface to request proofs from a server. It also allows you to encrypt your requests to the server by making use of the NSM attestation API.

**Homepage:** <https://self.xyz/>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| self | <devops@self.xyz> | <https://self.xyz/> |

## Source Code

* <https://self.xyz/>
* <https://github.com/self-xyz>
* <https://github.com/self-xyz/tee-prover-server>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{"podAntiAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"app":"tee-server-register-2"}},"topologyKey":"kubernetes.io/hostname"}]}}` | Pod affinity and anti-affinity rules |
| containerArgs | string | `"chmod +x /usr/bin/socat\n/usr/bin/socat tcp-listen:8888,fork,reuseaddr vsock-connect:7:8888 & /usr/bin/socat vsock-listen:8889,fork,reuseaddr TCP4:{{ .Values.db.url }}:5432 &\nEIF_PATH=/home/tee-server.eif ENCLAVE_CPU_COUNT=16 ENCLAVE_MEMORY_SIZE=100000\nnitro-cli run-enclave --enclave-cid=7 --cpu-count $ENCLAVE_CPU_COUNT --memory $ENCLAVE_MEMORY_SIZE --eif-path $EIF_PATH &\nyum update -y -q >/dev/null 2>&1 && yum install -y -q procps >/dev/null 2>&1\nsleep 300\necho \"postgres://{{ .Values.db.user }}:{{ .Values.db.password }}@host:5432/postgres\" | /usr/bin/socat -t 1 - VSOCK-CONNECT:7:8890 &\ntail -f /dev/null\n"` | Shell script arguments passed to the container |
| containerCommand | list | `["/bin/sh","-c"]` | Command to run in the container |
| db | object | `{"password":"postgres","url":"localhost","user":"postgres"}` | Database connection configuration |
| deploymentAnnotations | object | `{}` | Annotations to add to the deployment resource |
| dnsPolicy | string | `"ClusterFirst"` | DNS policy for the pod |
| envs | list | `[]` | Environment variables to set in the container |
| fullnameOverride | string | `""` | Override the full name of the chart |
| hostPID | bool | `true` | Run pod in the host's PID namespace |
| image | object | `{"pullPolicy":"Always","repository":"selfdotxyz/tee-server-register-instance-medium","tag":"latest"}` | Docker image configuration |
| imagePullSecrets | list | `[]` | List of image pull secrets for private registries |
| livenessProbe | object | `{"exec":{"command":["/bin/sh","-c","pgrep -f '^nitro-cli run-enclave' >/dev/null"]},"failureThreshold":5,"initialDelaySeconds":500,"periodSeconds":20,"successThreshold":1,"timeoutSeconds":1}` | Liveness probe configuration for the container |
| nameOverride | string | `""` | Override the name of the chart |
| nodeSelector | object | `{"alpha.eksctl.io/nodegroup-name":"pop-group-r6a-24xlarge"}` | Node selector for scheduling pods to specific nodes |
| podAnnotations | object | `{}` | Annotations to add to the pod template |
| progressDeadlineSeconds | int | `600` | Maximum time in seconds for a deployment to make progress |
| readinessProbe | object | `{"exec":{"command":["/bin/sh","-c","pgrep -f '^nitro-cli run-enclave' >/dev/null"]},"failureThreshold":3,"initialDelaySeconds":30,"periodSeconds":10,"successThreshold":1,"timeoutSeconds":1}` | Readiness probe configuration for the container |
| replicas | int | `1` | Number of pod replicas to deploy |
| resources | object | `{"limits":{"aws.ec2.nitro/nitro_enclaves":"4","hugepages-1Gi":"120Gi"},"requests":{"aws.ec2.nitro/nitro_enclaves":"4","cpu":"3","hugepages-1Gi":"120Gi"}}` | Resource requests and limits for the container |
| restartPolicy | string | `"Always"` | Pod restart policy |
| revisionHistoryLimit | int | `10` | Number of old ReplicaSets to retain for rollback |
| schedulerName | string | `"default-scheduler"` | Scheduler to use for the pod |
| securityContext | object | `{"privileged":true}` | Security context for the container |
| strategy | object | `{"rollingUpdate":{"maxSurge":0,"maxUnavailable":1},"type":"RollingUpdate"}` | Deployment update strategy |
| terminationGracePeriodSeconds | int | `30` | Time to wait before forcefully terminating the pod |
| tolerations | list | `[{"effect":"NoSchedule","operator":"Exists"},{"effect":"NoExecute","operator":"Exists"}]` | Tolerations for scheduling pods on tainted nodes |
| volumeMounts | list | `[{"mountPath":"/dev/hugepages","name":"hugepage-1gi"},{"mountPath":"/run/systemd","name":"systemd-run"},{"mountPath":"/sys/fs/cgroup","name":"cgroup","readOnly":true}]` | Volume mounts for the container |
| volumes | list | `[{"emptyDir":{"medium":"HugePages-1Gi"},"name":"hugepage-1gi"},{"emptyDir":{"medium":"HugePages-2Mi"},"name":"hugepage-2mi"},{"hostPath":{"path":"/run/systemd","type":"Directory"},"name":"systemd-run"},{"hostPath":{"path":"/sys/fs/cgroup","type":"DirectoryOrCreate"},"name":"cgroup"}]` | Volumes to mount into the pod |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs](https://github.com/norwoodj/helm-docs). To regenerate run `helm-docs` command at this folder.
