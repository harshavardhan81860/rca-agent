import os
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from kubernetes import client, config


PROMETHEUS_URL = os.getenv(
    "PROMETHEUS_URL",
    "http://127.0.0.1:9090"
).rstrip("/")

app = FastAPI(
    title="Kubernetes Autonomous RCA Agent",
    description="Receives alerts and investigates Kubernetes and Prometheus.",
    version="2.0.0",
)

k8s_core = None


class AlertmanagerWebhook(BaseModel):
    receiver: str | None = None
    status: str | None = None
    alerts: list[dict[str, Any]] = Field(default_factory=list)


def get_kubernetes_client():
    global k8s_core

    if k8s_core is not None:
        return k8s_core

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    k8s_core = client.CoreV1Api()
    return k8s_core


def escape_promql(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def query_prometheus(query: str) -> dict:
    try:
        response = httpx.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=15,
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") != "success":
            return {"error": "Prometheus query was unsuccessful"}

        return {
            "status": "success",
            "results": result.get("data", {}).get("result", []),
        }

    except Exception as exc:
        return {"error": str(exc)}


def investigate_pod(namespace: str, pod_name: str) -> dict:
    try:
        v1 = get_kubernetes_client()

        pod = v1.read_namespaced_pod(
            name=pod_name,
            namespace=namespace,
        )

        container_statuses = []
        container_logs = []

        for container in pod.status.container_statuses or []:
            state = container.state
            current_state = "unknown"
            reason = None
            message = None

            if state.running:
                current_state = "running"
            elif state.waiting:
                current_state = "waiting"
                reason = state.waiting.reason
                message = state.waiting.message
            elif state.terminated:
                current_state = "terminated"
                reason = state.terminated.reason
                message = state.terminated.message

            last_state = container.last_state

            last_state_details = {
                "reason": None,
                "message": None,
                "exit_code": None,
            }

            if last_state and last_state.terminated:
                last_state_details = {
                    "reason": last_state.terminated.reason,
                    "message": last_state.terminated.message,
                    "exit_code": last_state.terminated.exit_code,
                }

            container_statuses.append({
                "name": container.name,
                "ready": container.ready,
                "restart_count": container.restart_count,
                "state": current_state,
                "reason": reason,
                "message": message,
                "last_state": last_state_details,
            })



            def format_log_result(logs: str) -> dict:
                if not logs or not logs.strip():
                    return {
                        "status": "empty",
                        "logs": "",
                    }

                lower_logs = logs.lower()

                error_markers = (
                    "unable to retrieve container logs",
                    "error from server",
                    "container not found",
                    "failed to get container logs",
                )

                if any(marker in lower_logs for marker in error_markers):
                    return {
                        "status": "error",
                        "error": logs,
                    }

                return {
                    "status": "success",
                    "logs": logs,
                }

            # Collect logs from the current container instance.
            try:
                current_logs = v1.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=namespace,
                    container=container.name,
                    tail_lines=100,
                    timestamps=True,
                )

                current_log_result = format_log_result(current_logs)

            except Exception as exc:
                current_log_result = {
                    "status": "error",
                    "error": str(exc),
                }

            # Collect logs from the previous terminated instance.
            previous_log_result = None

            if container.restart_count > 0:
                try:
                    previous_logs = v1.read_namespaced_pod_log(
                        name=pod_name,
                        namespace=namespace,
                        container=container.name,
                        previous=True,
                        tail_lines=100,
                        timestamps=True,
                    )

                    previous_log_result = format_log_result(previous_logs)

                except Exception as exc:
                    previous_log_result = {
                        "status": "error",
                        "error": str(exc),
                    }


            container_logs.append({
                "container": container.name,
                "restart_count": container.restart_count,
                "current_logs": current_log_result,
                "previous_logs": previous_log_result,
            })

        events_result = v1.list_namespaced_event(
            namespace=namespace,
            field_selector=f"involvedObject.name={pod_name}",
            limit=20,
        )

        recent_events = [
            {
                "reason": event.reason,
                "message": event.message,
                "type": event.type,
                "count": event.count,
                "last_timestamp": str(
                    event.last_timestamp or event.event_time or ""
                ),
            }
            for event in events_result.items
        ]

        return {
            "status": "success",
            "pod": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "phase": pod.status.phase,
            "node": pod.spec.node_name,
            "pod_ready": next(
                (
                    condition.status == "True"
                    for condition in pod.status.conditions or []
                    if condition.type == "Ready"
                ),
                False,
            ),
            "containers": container_statuses,
            "container_logs": container_logs,
            "recent_events": recent_events,
        }

    except Exception as exc:
        return {"error": str(exc)}



def investigate_node(node_name: str) -> dict:
    try:
        v1 = get_kubernetes_client()
        node = v1.read_node(name=node_name)

        conditions = [
            {
                "type": condition.type,
                "status": condition.status,
                "reason": condition.reason,
                "message": condition.message,
            }
            for condition in node.status.conditions or []
        ]

        return {
            "status": "success",
            "node": node.metadata.name,
            "conditions": conditions,
        }

    except Exception as exc:
        return {"error": str(exc)}


def investigate_deployment(namespace: str, deployment_name: str) -> dict:
    try:
        v1 = get_kubernetes_client()
        apps_v1 = client.AppsV1Api()

        deployment = apps_v1.read_namespaced_deployment(
            name=deployment_name,
            namespace=namespace,
        )

        status = deployment.status
        spec = deployment.spec

        desired = spec.replicas or 0
        current = status.replicas or 0
        ready = status.ready_replicas or 0
        available = status.available_replicas or 0
        unavailable = status.unavailable_replicas or 0

        # Get pods belonging to this Deployment.
        match_labels = spec.selector.match_labels or {}

        selector = ",".join(
            f"{key}={value}"
            for key, value in match_labels.items()
        )

        pods = []
        findings = []
        all_events = []

        if selector:
            pod_list = v1.list_namespaced_pod(
                namespace=namespace,
                label_selector=selector,
            )

            for pod in pod_list.items:
                pod_name = pod.metadata.name
                pod_status = pod.status

                container_details = []

                for container in pod_status.container_statuses or []:
                    state = container.state

                    waiting_reason = None
                    waiting_message = None
                    terminated_reason = None

                    if state.waiting:
                        waiting_reason = state.waiting.reason
                        waiting_message = state.waiting.message

                    if state.terminated:
                        terminated_reason = state.terminated.reason

                    last_termination = None

                    if container.last_state and container.last_state.terminated:
                        last_termination = {
                            "reason": container.last_state.terminated.reason,
                            "exit_code": container.last_state.terminated.exit_code,
                            "message": container.last_state.terminated.message,
                        }

                    container_info = {
                        "name": container.name,
                        "ready": container.ready,
                        "restart_count": container.restart_count,
                        "waiting_reason": waiting_reason,
                        "waiting_message": waiting_message,
                        "terminated_reason": terminated_reason,
                        "last_termination": last_termination,
                    }

                    container_details.append(container_info)

                    # Detect common container failures.
                    if waiting_reason in (
                        "ImagePullBackOff",
                        "ErrImagePull",
                    ):
                        findings.append({
                            "type": "container",
                            "pod": pod_name,
                            "container": container.name,
                            "reason": waiting_reason,
                            "message": waiting_message,
                        })

                    if (
                        terminated_reason == "OOMKilled"
                        or (
                            last_termination
                            and last_termination["reason"] == "OOMKilled"
                        )
                    ):
                        findings.append({
                            "type": "container",
                            "pod": pod_name,
                            "container": container.name,
                            "reason": "OOMKilled",
                            "message": "Container was terminated because of memory exhaustion.",
                        })

                    if waiting_reason == "CrashLoopBackOff":
                        findings.append({
                            "type": "container",
                            "pod": pod_name,
                            "container": container.name,
                            "reason": "CrashLoopBackOff",
                            "message": waiting_message,
                        })

                # Collect pod conditions.
                pod_conditions = [
                    {
                        "type": condition.type,
                        "status": condition.status,
                        "reason": condition.reason,
                        "message": condition.message,
                    }
                    for condition in (pod_status.conditions or [])
                ]

                # Collect events for this pod.
                event_list = v1.list_namespaced_event(
                    namespace=namespace,
                    field_selector=f"involvedObject.name={pod_name}",
                    limit=30,
                )

                pod_events = []

                for event in event_list.items:
                    event_info = {
                        "pod": pod_name,
                        "reason": event.reason,
                        "message": event.message,
                        "type": event.type,
                        "count": event.count,
                    }

                    pod_events.append(event_info)
                    all_events.append(event_info)

                    if event.type == "Warning":
                        findings.append({
                            "type": "event",
                            "pod": pod_name,
                            "reason": event.reason,
                            "message": event.message,
                        })

                        # Detect Kubernetes health probe failures.
                        event_message = (event.message or "").lower()

                        if "readiness probe failed" in event_message:
                            findings.append({
                                "type": "probe_failure",
                                "probe": "Readiness",
                                "pod": pod_name,
                                "reason": event.reason,
                                "message": event.message,
                            })

                        elif "liveness probe failed" in event_message:
                            findings.append({
                                "type": "probe_failure",
                                "probe": "Liveness",
                                "pod": pod_name,
                                "reason": event.reason,
                                "message": event.message,
                            })

                        elif "startup probe failed" in event_message:
                            findings.append({
                                "type": "probe_failure",
                                "probe": "Startup",
                                "pod": pod_name,
                                "reason": event.reason,
                                "message": event.message,
                            })


                # Determine pod readiness.
                pod_ready = any(
                    condition.type == "Ready"
                    and condition.status == "True"
                    for condition in (pod_status.conditions or [])
                )

                pods.append({
                    "name": pod_name,
                    "phase": pod_status.phase,
                    "node": pod.spec.node_name,
                    "ready": pod_ready,
                    "restarts": sum(
                        container.restart_count
                        for container in (pod_status.container_statuses or [])
                    ),
                    "containers": container_details,
                    "conditions": pod_conditions,
                    "events": pod_events,
                })

        # Collect Deployment-specific events.
        deployment_events = v1.list_namespaced_event(
            namespace=namespace,
            field_selector=(
                f"involvedObject.name={deployment_name},"
                "involvedObject.kind=Deployment"
            ),
            limit=30,
        )

        for event in deployment_events.items:
            all_events.append({
                "resource": deployment_name,
                "reason": event.reason,
                "message": event.message,
                "type": event.type,
                "count": event.count,
            })

        # Generate evidence-based probable cause.

        # Collect specific container failure evidence.
        container_failure_reasons = (
            "ImagePullBackOff",
            "ErrImagePull",
            "OOMKilled",
        )

        container_failures = [
            finding
            for finding in findings
            if finding.get("reason") in container_failure_reasons
        ]

        image_findings = [
            finding
            for finding in container_failures
            if finding.get("reason") in (
                "ImagePullBackOff",
                "ErrImagePull",
            )
        ]

        # Collect OOMKilled evidence separately so it takes
        # precedence over the generic container failure diagnosis.
        oom_findings = [
            finding
            for finding in container_failures
            if finding.get("reason") == "OOMKilled"
        ]

        # Collect failed scheduling evidence.
        scheduling_findings = [
            finding
            for finding in findings
            if finding.get("reason") == "FailedScheduling"
        ]

        # Collect health probe failure evidence.
        probe_findings = [
            finding
            for finding in findings
            if finding.get("type") == "probe_failure"
        ]

        if desired == 0:
            probable_cause = (
                "Deployment is configured with zero desired replicas. "
                "Check whether it has intentionally been scaled down."
            )

        elif not pods:
            probable_cause = (
                "Deployment has no matching pods. Investigate its "
                "pod selector, ReplicaSet, scheduling and events."
            )

        elif scheduling_findings:
            scheduling_messages = list(dict.fromkeys(
                finding.get("message", "")
                for finding in scheduling_findings
                if finding.get("message")
            ))

            probable_cause = (
                "Kubernetes scheduler cannot place the Deployment pods. "
                "The scheduling failure indicates resource or node "
                "capacity constraints. Scheduler evidence: "
                + " | ".join(scheduling_messages)
            )

        elif image_findings:
            image_messages = " ".join(
                finding.get("message", "")
                for finding in image_findings
            ).lower()

            image_details = list(dict.fromkeys(
                finding.get("message", "")
                for finding in image_findings
                if finding.get("message")
            ))

            if (
                "not found" in image_messages
                or "manifest unknown" in image_messages
            ):
                probable_cause = (
                    "Container image pull failed because the requested "
                    "image repository or tag does not exist in the "
                    "container registry. Verify the image name, repository "
                    "and tag in the Deployment specification. Registry "
                    "evidence: " + " | ".join(image_details)
                )

            elif (
                "unauthorized" in image_messages
                or "authentication required" in image_messages
                or "denied" in image_messages
            ):
                probable_cause = (
                    "Container image pull failed because the registry "
                    "rejected access or authentication. Verify registry "
                    "credentials, imagePullSecrets and the ServiceAccount. "
                    "Registry evidence: " + " | ".join(image_details)
                )

            elif any(term in image_messages for term in (
                "timeout",
                "i/o timeout",
                "no such host",
                "connection refused",
                "network is unreachable",
            )):
                probable_cause = (
                    "Container image pull failed because the registry "
                    "could not be reached. Investigate DNS resolution, "
                    "network connectivity, firewall rules and registry "
                    "availability. Registry evidence: "
                    + " | ".join(image_details)
                )

            else:
                probable_cause = (
                    "Container image pull failed. Verify the image "
                    "repository, tag, registry availability and access "
                    "credentials. Registry evidence: "
                    + " | ".join(image_details)
                )

        elif oom_findings:
            oom_details = list(dict.fromkeys(
                finding.get("message", "")
                for finding in oom_findings
                if finding.get("message")
            ))

            probable_cause = (
                "Deployment container was terminated due to memory "
                "exhaustion. Kubernetes reported OOMKilled. This is the "
                "primary failure; CrashLoopBackOff, if also present, is "
                "a consequence of the container repeatedly restarting. "
                "Inspect the container memory limit, actual memory usage "
                "and application memory consumption."
            )

            if oom_details:
                probable_cause += (
                    " OOM evidence: " + " | ".join(oom_details)
                )

        elif container_failures:
            failure_details = list(dict.fromkeys(
                (
                    finding.get("reason", "ContainerFailure")
                    + (
                        ": " + finding.get("message", "")
                        if finding.get("message")
                        else ""
                    )
                )
                for finding in container_failures
            ))

            probable_cause = (
                "Deployment pods have container-level failures. "
                "Detected evidence: "
                + " | ".join(failure_details)
                + ". Investigate the container image, application "
                "logs, memory limits and exit status."
            )

        elif probe_findings:
            probe_details = list(dict.fromkeys(
                (
                    finding.get("probe", "Health")
                    + " probe failed for pod "
                    + finding.get("pod", "unknown")
                    + (
                        ": " + finding.get("message", "")
                        if finding.get("message")
                        else ""
                    )
                )
                for finding in probe_findings
            ))

            probable_cause = (
                "Kubernetes recorded health probe failures for the "
                "Deployment. Readiness failures can prevent pods from "
                "receiving traffic, while liveness and startup failures "
                "can cause container restarts. Probe evidence: "
                + " | ".join(probe_details)
                + ". Check probe configuration and application health."
            )

        elif available >= desired and desired > 0:
            probable_cause = (
                "Deployment currently has the expected number of "
                "available replicas. The alert may have recovered "
                "or may contain stale information."
            )

        elif findings:
            reasons = list(dict.fromkeys(
                finding["reason"]
                for finding in findings
                if finding.get("reason")
            ))

            probable_cause = (
                "Deployment has fewer available replicas than desired. "
                "Observed failure evidence: "
                + ", ".join(reasons)
                + ". Review the findings and pod events."
            )

        else:
            probable_cause = (
                f"Deployment has insufficient available replicas. "
                f"Desired: {desired}, available: {available}. "
                "No specific container failure was identified. "
                "Investigate scheduling, resource constraints, "
                "readiness probes and ReplicaSet events."
            )

        conditions = [
            {
                "type": condition.type,
                "status": condition.status,
                "reason": condition.reason,
                "message": condition.message,
            }
            for condition in (status.conditions or [])
        ]

        return {
            "status": "success",
            "deployment": deployment.metadata.name,
            "namespace": namespace,
            "replicas": {
                "desired": desired,
                "current": current,
                "ready": ready,
                "available": available,
                "unavailable": unavailable,
            },
            "conditions": conditions,
            "pods": pods,
            "findings": findings,
            "events": all_events,
            "probable_cause": probable_cause,
        }

    except Exception as exc:
        return {
            "status": "error",
            "deployment": deployment_name,
            "namespace": namespace,
            "error": str(exc),
        }

def collect_prometheus_metrics(
    namespace: str,
    pod: str,
    node: str,
    deployment: str = "unknown",
    deployment_pods: list | None = None,
) -> dict:
    metrics = {}

    # Cluster-wide worker-node capacity metrics.
    metrics["node_capacity"] = {
        "allocatable_cpu": query_prometheus(
            'kube_node_status_allocatable{resource="cpu"}'
        ),
        "allocatable_memory": query_prometheus(
            'kube_node_status_allocatable{resource="memory"}'
        ),
        "allocatable_pods": query_prometheus(
            'kube_node_status_allocatable{resource="pods"}'
        ),
    }

    # CPU and memory requests from containers in the affected namespace.
    if namespace != "unknown":
        safe_namespace = escape_promql(namespace)

        metrics["namespace_resource_requests"] = query_prometheus(
            "kube_pod_container_resource_requests"
            f'{{namespace="{safe_namespace}"}}'
        )

    if namespace != "unknown":
        ns = escape_promql(namespace)

        # Deployment-level metrics.
        if deployment != "unknown":
            deployment_name = escape_promql(deployment)

            deployment_selector = (
                f'namespace="{ns}",deployment="{deployment_name}"'
            )

            deployment_queries = {
                "desired_replicas":
                    f'kube_deployment_spec_replicas{{{deployment_selector}}}',
                "current_replicas":
                    f'kube_deployment_status_replicas{{{deployment_selector}}}',
                "available_replicas":
                    f'kube_deployment_status_replicas_available{{{deployment_selector}}}',
                "unavailable_replicas":
                    f'kube_deployment_status_replicas_unavailable{{{deployment_selector}}}',
                "updated_replicas":
                    f'kube_deployment_status_replicas_updated{{{deployment_selector}}}',
            }

            metrics["deployment"] = {}

            for metric_name, query in deployment_queries.items():
                metrics["deployment"][metric_name] = query_prometheus(query)

            # Collect metrics for every pod belonging to this Deployment.
            metrics["deployment_pods"] = {}

            for pod_details in deployment_pods or []:
                pod_name = pod_details.get("name")

                if not pod_name:
                    continue

                safe_pod = escape_promql(pod_name)

                pod_selector = (
                    f'namespace="{ns}",pod="{safe_pod}"'
                )

                metrics["deployment_pods"][pod_name] = {
                    "restarts": query_prometheus(
                        f'kube_pod_container_status_restarts_total{{{pod_selector}}}'
                    ),
                    "phase": query_prometheus(
                        f'kube_pod_status_phase{{{pod_selector}}}'
                    ),
                    "ready": query_prometheus(
                        f'kube_pod_status_ready{{{pod_selector},condition="true"}}'
                    ),
                }

        # Individual pod metrics.
        if pod != "unknown":
            pod_name = escape_promql(pod)
            pod_selector = f'namespace="{ns}",pod="{pod_name}"'

            metrics["pod_restarts"] = query_prometheus(
                f'kube_pod_container_status_restarts_total{{{pod_selector}}}'
            )

            metrics["pod_phase"] = query_prometheus(
                f'kube_pod_status_phase{{{pod_selector}}}'
            )

            metrics["pod_ready"] = query_prometheus(
                f'kube_pod_status_ready{{{pod_selector},condition="true"}}'
            )

    if node != "unknown":
        node_name = escape_promql(node)

        metrics["node_ready"] = query_prometheus(
            f'kube_node_status_condition{{node="{node_name}",condition="Ready",status="true"}}'
        )

    return metrics


def analyze_deployment_capacity(
    prometheus_metrics: dict,
    deployment_details: dict,
) -> dict:
    """
    Compare affected Deployment pod requests against
    worker-node allocatable CPU and memory.
    """

    def get_results(metric_data):
        if not isinstance(metric_data, dict):
            return []

        if metric_data.get("status") != "success":
            return []

        return metric_data.get("results", [])

    capacity_metrics = prometheus_metrics.get(
        "node_capacity", {}
    )

    cpu_results = get_results(
        capacity_metrics.get("allocatable_cpu")
    )
    memory_results = get_results(
        capacity_metrics.get("allocatable_memory")
    )
    pod_results = get_results(
        capacity_metrics.get("allocatable_pods")
    )

    # Build node capacity information.
    nodes = {}

    for item in cpu_results:
        node_name = item.get("metric", {}).get("node")
        value = item.get("value", [None, None])[1]

        if node_name and value is not None:
            nodes.setdefault(node_name, {})["cpu_cores"] = float(value)

    for item in memory_results:
        node_name = item.get("metric", {}).get("node")
        value = item.get("value", [None, None])[1]

        if node_name and value is not None:
            memory_bytes = float(value)

            nodes.setdefault(node_name, {}).update({
                "memory_bytes": memory_bytes,
                "memory_gib": round(
                    memory_bytes / (1024 ** 3), 2
                ),
            })

    for item in pod_results:
        node_name = item.get("metric", {}).get("node")
        value = item.get("value", [None, None])[1]

        if node_name and value is not None:
            nodes.setdefault(node_name, {})["max_pods"] = int(
                float(value)
            )

    # Identify only pods belonging to this Deployment.
    deployment_pods = deployment_details.get("pods", [])

    target_pods = {
        pod.get("name")
        for pod in deployment_pods
        if pod.get("name")
    }

    # Read resource requests from Prometheus.
    request_results = get_results(
        prometheus_metrics.get("namespace_resource_requests")
    )

    requests_by_pod = {}

    for item in request_results:
        labels = item.get("metric", {})
        pod_name = labels.get("pod")
        resource = labels.get("resource")
        value = item.get("value", [None, None])[1]

        if (
            pod_name not in target_pods
            or resource not in ("cpu", "memory")
            or value is None
        ):
            continue

        requests_by_pod.setdefault(
            pod_name,
            {"cpu_cores": 0.0, "memory_bytes": 0.0},
        )

        if resource == "cpu":
            requests_by_pod[pod_name]["cpu_cores"] += float(value)

        elif resource == "memory":
            requests_by_pod[pod_name]["memory_bytes"] += float(value)

    # Compare each pod's requests with every node.
    pod_analysis = []

    for pod_name in sorted(target_pods):
        request = requests_by_pod.get(pod_name)

        if request is None:
            pod_analysis.append({
                "pod": pod_name,
                "status": "metrics_unavailable",
            })
            continue

        cpu_request = request["cpu_cores"]
        memory_request = request["memory_bytes"]

        cpu_matching_nodes = []
        memory_matching_nodes = []
        nodes_matching_both = []

        for node_name, capacity in nodes.items():
            node_cpu = capacity.get("cpu_cores")
            node_memory = capacity.get("memory_bytes")

            if node_cpu is not None and cpu_request <= node_cpu:
                cpu_matching_nodes.append(node_name)

            if (
                node_memory is not None
                and memory_request <= node_memory
            ):
                memory_matching_nodes.append(node_name)

            if (
                node_cpu is not None
                and node_memory is not None
                and cpu_request <= node_cpu
                and memory_request <= node_memory
            ):
                nodes_matching_both.append(node_name)

        pod_analysis.append({
            "pod": pod_name,
            "status": "analyzed",
            "requests": {
                "cpu_cores": cpu_request,
                "memory_gib": round(
                    memory_request / (1024 ** 3), 2
                ),
            },
            "nodes_matching_cpu": cpu_matching_nodes,
            "nodes_matching_memory": memory_matching_nodes,
            "nodes_matching_both": nodes_matching_both,
            "fits_any_node": bool(nodes_matching_both),
            "blocking_resources": [
                resource
                for resource, matches in (
                    ("cpu", cpu_matching_nodes),
                    ("memory", memory_matching_nodes),
                )
                if not matches and nodes
            ],
        })

    if not nodes or not pod_analysis:
        status = "insufficient_metrics"
    elif any(
        pod.get("status") == "metrics_unavailable"
        for pod in pod_analysis
    ):
        status = "partial"
    else:
        status = "success"

    return {
        "status": status,
        "comparison": "pod requests versus node allocatable capacity",
        "nodes": nodes,
        "pods": pod_analysis,
    }

def analyze_alert(alert: dict[str, Any]) -> dict:
    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})

    alert_name = labels.get("alertname", "Unknown")
    severity = labels.get("severity", "unknown")
    namespace = labels.get("namespace", "unknown")
    pod = labels.get("pod", "unknown")
    node = labels.get("node", "unknown")
    deployment = labels.get("deployment", "unknown")

    categories = {
        "PodCrashLooping": (
            "Application",
            "Container is repeatedly crashing. Investigate container state, "
            "restart count, events and application logs.",
        ),
        "PodRestartingFrequently": (
            "Application",
            "Pod has restarted frequently. Investigate container state, "
            "restart count, memory usage and health probes.",
        ),
        "PodNotReady": (
            "Kubernetes",
            "Pod readiness needs to be verified against live evidence.",
        ),
        "NodeNotReady": (
            "Infrastructure",
            "Node may be unhealthy. Investigate node conditions, "
            "kubelet, network and EC2 health.",
        ),
        "DeploymentReplicasMismatch": (
            "Application",
            "Deployment has fewer available replicas than desired. "
            "Investigate pod scheduling, image pulls and resource limits.",
        ),
        "KubePodPending": (
            "Infrastructure",
            "Kubernetes cannot schedule one or more pods. "
            "Investigate node capacity, CPU and memory requests, "
            "pod limits, taints and scheduling constraints.",
        ),
    }

    category, explanation = categories.get(
        alert_name,
        (
            "Unknown",
            "No matching RCA rule exists yet. Further investigation is required.",
        ),
    )

    investigation = {}

    if alert_name in ("PodCrashLooping", "PodRestartingFrequently", "PodNotReady"):
        if pod != "unknown" and namespace != "unknown":
            investigation["pod_details"] = investigate_pod(namespace, pod)

    if alert_name == "NodeNotReady" and node != "unknown":
        investigation["node_details"] = investigate_node(node)

    # Evidence-based diagnosis for DeploymentReplicasMismatch.
    if alert_name in ("DeploymentReplicasMismatch", "KubePodPending"):
        if namespace != "unknown" and deployment != "unknown":
            investigation["deployment_details"] = investigate_deployment(
                namespace,
                deployment,
            )

            deployment_details = investigation["deployment_details"]

            if deployment_details.get("status") == "success":
                deployment_findings = deployment_details.get(
                    "findings", []
                )

                scheduling_findings = [
                    finding
                    for finding in deployment_findings
                    if finding.get("reason") == "FailedScheduling"
                ]

                image_findings = [
                    finding
                    for finding in deployment_findings
                    if finding.get("reason") in (
                        "ImagePullBackOff",
                        "ErrImagePull",
                    )
                ]

                if scheduling_findings:
                    scheduling_text = " ".join(
                        finding.get("message", "")
                        for finding in scheduling_findings
                    ).lower()

                    if any(term in scheduling_text for term in (
                        "insufficient cpu",
                        "insufficient memory",
                        "too many pods",
                    )):
                        category = "Infrastructure"
                    else:
                        category = "Kubernetes"

                elif image_findings:
                    category = "Container Registry"

                explanation = deployment_details["probable_cause"]
            else:
                explanation = (
                    "Unable to investigate the deployment using the "
                    "Kubernetes API. Check the deployment name, namespace "
                    "and RCA agent permissions."
                )
        else:
            explanation = (
                "Deployment investigation requires both namespace and "
                "deployment labels in the incoming alert."
            )


    deployment_pods = investigation.get(
        "deployment_details", {}
    ).get("pods", [])

    investigation["prometheus_metrics"] = collect_prometheus_metrics(
        namespace,
        pod,
        node,
        deployment,
        deployment_pods,
    )
    # Compare Deployment resource requests against node capacity.
    if alert_name in ("DeploymentReplicasMismatch", "KubePodPending"):
        investigation["capacity_analysis"] = (
            analyze_deployment_capacity(
                investigation["prometheus_metrics"],
                investigation.get("deployment_details", {}),
            )
        )
   # Evidence-based diagnosis for pod crash alerts.
    if alert_name in ("PodCrashLooping", "PodRestartingFrequently"):
        investigation["crash_diagnosis"] = diagnose_pod_crashes(
            investigation.get("pod_details", {}),
            investigation.get("prometheus_metrics", {}),
        )

        explanation = investigation["crash_diagnosis"]["probable_cause"]

    # Evidence-based diagnosis for PodNotReady.
    if alert_name == "PodNotReady":
        pod_details = investigation.get("pod_details", {})
        pod_metrics = investigation["prometheus_metrics"].get("pod_phase", {})

        kubernetes_health = None
        prometheus_running = None

        # Check the live Kubernetes pod state.
        if (
            pod_details.get("status") == "success"
            and isinstance(pod_details.get("phase"), str)
            and isinstance(pod_details.get("pod_ready"), bool)
        ):
            phase = pod_details["phase"]
            ready = pod_details["pod_ready"]
            containers = pod_details.get("containers", [])

            containers_ready = all(
                container.get("ready") is True
                for container in containers
            )

            kubernetes_health = (
                phase == "Running"
                and ready is True
                and containers_ready
            )

        # Check the Prometheus Running phase metric.
        if (
            isinstance(pod_metrics, dict)
            and pod_metrics.get("status") == "success"
        ):
            results = pod_metrics.get(
                "results",
                pod_metrics.get("data", {}).get("result", [])
            )

            if results:
                running_series = [
                    item for item in results
                    if item.get("metric", {}).get("phase") == "Running"
                ]

                if running_series:
                    prometheus_running = any(
                        item.get("value", [None, "0"])[1] == "1"
                        for item in running_series
                    )
                else:
                    prometheus_running = False

        if kubernetes_health is False:
            diagnosis_status = "active"
            explanation = (
                "Kubernetes confirms that the pod is unhealthy. "
                "Investigate its phase, readiness condition, container states, "
                "events and logs."
            )

        elif kubernetes_health is True and prometheus_running is True:
            diagnosis_status = "recovered_or_stale"
            explanation = (
                "The alert reports PodNotReady, but live Kubernetes and "
                "Prometheus evidence show that the pod is Running and Ready. "
                "The alert may have recovered or be stale. Check whether "
                "Alertmanager has received the resolved notification."
            )

        elif (
            kubernetes_health is not None
            and prometheus_running is not None
            and kubernetes_health != prometheus_running
        ):
            diagnosis_status = "conflicting_evidence"
            explanation = (
                "Kubernetes and Prometheus disagree about the pod's health. "
                "Check metric freshness, scrape status and pod conditions."
            )

        else:
            diagnosis_status = "inconclusive"
            explanation = (
                "There is not enough reliable live evidence to determine "
                "whether the pod is healthy. Check Kubernetes API access "
                "and Prometheus metric availability."
            )

        investigation["diagnosis"] = {
            "status": diagnosis_status,
            "kubernetes_healthy": kubernetes_health,
            "prometheus_running": prometheus_running,
        }

    # Generate evidence-based remediation recommendations.
    remediation = {
        "status": "not_generated",
        "priority": "Not set",
        "automatic_action": False,
        "reason": "No specific remediation rule matched this alert.",
        "evidence": [],
        "recommendations": [],
    }

    if alert_name in ("DeploymentReplicasMismatch", "KubePodPending"):
        deployment_details = investigation.get(
            "deployment_details", {}
        )

        deployment_findings = deployment_details.get(
            "findings", []
        )

        detected_reasons = {
            finding.get("reason")
            for finding in deployment_findings
        }

        evidence = []
        recommendations = []
        matched_failures = []

        # --------------------------------------------------
        # 1. FailedScheduling: CPU, memory and pod capacity
        # --------------------------------------------------
        scheduling_findings = [
            finding
            for finding in deployment_findings
            if finding.get("reason") == "FailedScheduling"
        ]

        if scheduling_findings:
            matched_failures.append("FailedScheduling")

            messages = list(dict.fromkeys(
                finding.get("message", "")
                for finding in scheduling_findings
                if finding.get("message")
            ))

            evidence.extend(messages)
            scheduling_text = " ".join(messages).lower()

            capacity_analysis = investigation.get(
                "capacity_analysis", {}
            )

            capacity_nodes = capacity_analysis.get("nodes", {})
            capacity_pods = capacity_analysis.get("pods", [])

            max_node_cpu = max(
                (
                    node.get("cpu_cores", 0)
                    for node in capacity_nodes.values()
                ),
                default=0,
            )

            max_node_memory = max(
                (
                    node.get("memory_gib", 0)
                    for node in capacity_nodes.values()
                ),
                default=0,
            )

            oversized_pods = [
                pod
                for pod in capacity_pods
                if pod.get("status") == "analyzed"
                and pod.get("fits_any_node") is False
                and pod.get("blocking_resources")
            ]

            for pod in capacity_pods:
                if pod.get("status") != "analyzed":
                    continue

                requests = pod.get("requests", {})

                evidence.append(
                    f"Pod {pod.get('pod')} requests "
                    f"{requests.get('cpu_cores')} CPU cores and "
                    f"{requests.get('memory_gib')} GiB memory."
                )

                if pod.get("fits_any_node") is False:
                    evidence.append(
                        f"Pod {pod.get('pod')} cannot fit on any "
                        f"worker node. Blocking resources: "
                        f"{', '.join(pod.get('blocking_resources', []))}."
                    )

            if capacity_nodes:
                evidence.append(
                    f"Largest worker-node allocatable capacity: "
                    f"{max_node_cpu} CPU cores and "
                    f"{max_node_memory} GiB memory."
                )

            if "insufficient cpu" in scheduling_text:
                recommendations.append(
                    "Review CPU requests and compare them with "
                    "worker-node allocatable CPU."
                )

            if "insufficient memory" in scheduling_text:
                recommendations.append(
                    "Review memory requests and compare them with "
                    "worker-node allocatable memory."
                )

            if "too many pods" in scheduling_text:
                recommendations.append(
                    "Check maximum pod capacity, current pod count "
                    "and EKS node networking configuration."
                )

            if oversized_pods:
                recommendations.extend([
                    "Right-size CPU and memory requests. At least "
                    "one affected pod requests more resources than "
                    "every worker node can provide.",
                    "Do not scale the node group to solve oversized "
                    "requests. Correct the Deployment resource "
                    "requests first.",
                ])

            elif capacity_analysis.get("status") == "success":
                recommendations.extend([
                    "Review existing CPU and memory requests on "
                    "worker nodes. Allocatable capacity does not "
                    "represent remaining schedulable capacity.",
                    "If workload requests are justified and existing "
                    "allocations leave insufficient capacity, "
                    "evaluate scaling the EKS managed node group.",
                ])

            else:
                recommendations.append(
                    "Capacity metrics are incomplete. Verify node "
                    "capacity and allocations before considering "
                    "node-group scaling."
                )

            recommendations.extend([
                "Inspect node resource allocation using "
                "'kubectl describe nodes'.",
                "Inspect pod placement using "
                "'kubectl get pods -A -o wide'.",
                "Check node conditions, taints, affinity rules "
                "and topology constraints.",
            ])

        # --------------------------------------------------
        # 2. ImagePullBackOff / ErrImagePull
        # --------------------------------------------------
        image_findings = [
            finding
            for finding in deployment_findings
            if finding.get("reason") in (
                "ImagePullBackOff",
                "ErrImagePull",
            )
        ]

        if image_findings:
            matched_failures.append("ImagePullFailure")

            for finding in image_findings:
                evidence.append(
                    f"Pod {finding.get('pod')}, container "
                    f"{finding.get('container')}: "
                    f"{finding.get('reason')}."
                )

                if finding.get("message"):
                    evidence.append(finding["message"])

            recommendations.extend([
                "Verify the container image repository and image "
                "tag in the Deployment specification.",
                "Check whether the image exists in the container "
                "registry and is accessible.",
                "For private registries, verify imagePullSecrets, "
                "credentials and Kubernetes service account configuration.",
                "Inspect the pod events using "
                "'kubectl describe pod <pod-name> -n <namespace>'.",
            ])

        # --------------------------------------------------
        # 3. Identify OOMKilled before processing CrashLoopBackOff
        # --------------------------------------------------
        oom_findings = [
            finding
            for finding in deployment_findings
            if finding.get("reason") == "OOMKilled"
        ]

        # --------------------------------------------------
        # 4. CrashLoopBackOff
        # --------------------------------------------------
        crash_findings = [
            finding
            for finding in deployment_findings
            if finding.get("reason") == "CrashLoopBackOff"
        ]

        if crash_findings:
            matched_failures.append("CrashLoopBackOff")

            for finding in crash_findings:
                evidence.append(
                    f"Pod {finding.get('pod')}, container "
                    f"{finding.get('container')}: CrashLoopBackOff."
                )

                if finding.get("message"):
                    evidence.append(finding["message"])

            if not oom_findings:
                recommendations.extend([
                    "Inspect the previous container logs using "
                    "'kubectl logs <pod-name> -n <namespace> "
                    "--previous -c <container-name>'.",
                    "Check the container exit code and last termination "
                    "reason using 'kubectl describe pod'.",
                    "Review application configuration, environment "
                    "variables, secrets and startup dependencies.",
                    "Check readiness and liveness probe configuration "
                    "if probes are contributing to repeated restarts.",
                ])

        # --------------------------------------------------
        # 5. OOMKilled
        # --------------------------------------------------
        if oom_findings:
            matched_failures.append("OOMKilled")

            for finding in oom_findings:
                evidence.append(
                    f"Pod {finding.get('pod')}, container "
                    f"{finding.get('container')}: OOMKilled."
                )

                if finding.get("message"):
                    evidence.append(finding["message"])

            recommendations.extend([
                "Inspect container memory limits and requests "
                "in the Deployment specification.",
                "Review historical memory usage and identify "
                "whether the application has a memory leak or "
                "unexpected memory consumption.",
                "Inspect previous container logs using "
                "'kubectl logs <pod-name> -n <namespace> "
                "--previous -c <container-name>'.",
                "Adjust memory requests and limits based on "
                "measured application requirements.",
            ])

        # --------------------------------------------------
        # --------------------------------------------------
        # 5. Readiness / Liveness / Startup probe failures
        # --------------------------------------------------
        probe_findings = [
            finding
            for finding in deployment_findings
            if finding.get("type") == "probe_failure"
        ]

        for probe_type in ("Readiness", "Liveness", "Startup"):
            matching_probe_findings = [
                finding
                for finding in probe_findings
                if finding.get("probe") == probe_type
            ]

            if not matching_probe_findings:
                continue

            matched_failures.append(f"{probe_type}ProbeFailure")

            for finding in matching_probe_findings:
                evidence.append(
                    f"{probe_type} probe failed for pod "
                    f"{finding.get('pod')}."
                )

                if finding.get("message"):
                    evidence.append(finding["message"])

            if probe_type == "Readiness":
                recommendations.extend([
                    "Verify the readiness probe HTTP path, port, "
                    "scheme and expected response.",
                    "Check whether the application is ready to serve "
                    "traffic and whether required dependencies are available.",
                    "Review readiness probe timeoutSeconds, "
                    "periodSeconds and failureThreshold.",
                ])

            elif probe_type == "Liveness":
                recommendations.extend([
                    "Inspect application logs for crashes, deadlocks "
                    "or unresponsive processes.",
                    "Verify the liveness probe path, port, timeout "
                    "and failure threshold.",
                    "Check whether the liveness probe is too aggressive "
                    "for the application's normal response time.",
                ])

            elif probe_type == "Startup":
                recommendations.extend([
                    "Check application startup logs and initialization "
                    "dependencies.",
                    "Review startup probe initialDelaySeconds, "
                    "periodSeconds, timeoutSeconds and failureThreshold.",
                    "Allow sufficient startup time before liveness "
                    "or readiness checks take effect.",
                ])

            recommendations.append(
                "Inspect probe-related pod events using "
                "'kubectl describe pod <pod-name> -n <namespace>'."
            )

        # --------------------------------------------------
        # 6. Generate combined remediation
        # --------------------------------------------------

        # --------------------------------------------------
        if matched_failures:
            remediation = {
                "status": "generated",
                "priority": (
                    "High"
                    if (
                        severity.lower() == "critical"
                        or "OOMKilled" in matched_failures
                    )
                    else "Medium"
                ),
                "automatic_action": False,
                "reason": (
                    "The agent detected the following Deployment "
                    "failure types: "
                    + ", ".join(matched_failures)
                    + ". Recommendations are based on live "
                    "Kubernetes and Prometheus evidence."
                ),
                "evidence": list(dict.fromkeys(evidence)),
                "recommendations": list(
                    dict.fromkeys(recommendations)
                ),
            }

    return {
        "alert_name": alert_name,
        "severity": severity,
        "status": alert.get("status", "unknown"),
        "category": category,
        "namespace": namespace,
        "pod": pod,
        "node": node,
        "deployment": deployment,
        "summary": annotations.get("summary", ""),
        "description": annotations.get("description", ""),
        "probable_cause": explanation,
        "remediation": remediation,
        "investigation": investigation,
        "starts_at": alert.get("startsAt"),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
def home():
    return {
        "service": "Kubernetes Autonomous RCA Agent",
        "status": "running",
        "version": "2.0.0",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/webhook/alerts")
def receive_alerts(payload: AlertmanagerWebhook):
    results = []

    for alert in payload.alerts:
        alert_status = str(
            alert.get("status") or payload.status or "unknown"
        ).lower()

        labels = alert.get("labels") or {}

        alert_info = {
            "alertname": labels.get("alertname"),
            "namespace": labels.get("namespace"),
            "pod": labels.get("pod"),
            "status": alert_status,
        }

        if alert_status == "firing":
            results.append({
                **alert_info,
                "analysis": analyze_alert(alert),
            })

        elif alert_status == "resolved":
            results.append({
                **alert_info,
                "message": "Alert resolved. New RCA investigation skipped.",
            })

        else:
            results.append({
                **alert_info,
                "message": "Unknown alert status. Investigation skipped.",
            })

    return {
        "message": "Alertmanager webhook received",
        "receiver": payload.receiver,
        "overall_status": payload.status,
        "alerts_received": len(results),
        "analysis": results,
    }


@app.post("/analyze")
def analyze_single_alert(alert: dict[str, Any]):
    if not isinstance(alert.get("labels", {}), dict):
        raise HTTPException(
            status_code=400,
            detail="Alert labels must be a JSON object",
        )

    return analyze_alert(alert)


def diagnose_pod_crashes(
    pod_details: dict,
    prometheus_metrics: dict
) -> dict:
    """Diagnose pod crashes using Kubernetes logs, events and Prometheus evidence."""

    findings = []
    restart_count = 0
    container_reasons = []
    container_messages = []
    exit_codes = []
    collected_logs = []
    seen_logs = set()

    if pod_details.get("status") != "success":
        return {
            "status": "inconclusive",
            "probable_cause": "Could not retrieve live Kubernetes pod details.",
            "findings": findings,
        }

    # 1. Inspect container states and previous termination details.
    for container in pod_details.get("containers", []):
        name = container.get("name", "unknown")
        count = container.get("restart_count", 0) or 0
        reason = container.get("reason")
        message = container.get("message") or ""

        restart_count += count

        if reason:
            container_reasons.append(reason)
            findings.append(
                f"Container {name} current state reason: {reason}."
            )

        if message:
            container_messages.append(message)

        last_state = container.get("last_state") or {}
        last_reason = last_state.get("reason")
        last_message = last_state.get("message") or ""
        exit_code = last_state.get("exit_code")

        if last_reason:
            container_reasons.append(last_reason)
            findings.append(
                f"Container {name} previous termination reason: {last_reason}."
            )

        if last_message:
            container_messages.append(last_message)

        if exit_code is not None:
            try:
                exit_codes.append(int(exit_code))
                findings.append(
                    f"Container {name} previous exit code: {exit_code}."
                )
            except (TypeError, ValueError):
                pass

        if count > 0:
            findings.append(
                f"Container {name} has restarted {count} time(s)."
            )

    # 2. Inspect current and previous container logs.
    for log_entry in pod_details.get("container_logs", []):
        for log_type in ("current_logs", "previous_logs"):
            log_result = log_entry.get(log_type) or {}

            if log_result.get("status") == "success":
                logs = log_result.get("logs") or ""

                if logs.strip() and logs not in seen_logs:
                    collected_logs.append(logs)
                    seen_logs.add(logs)

    combined_logs = "\n".join(collected_logs)

    # Keep only useful error-related log lines in the findings.
    error_keywords = (
        "error",
        "exception",
        "traceback",
        "failed",
        "failure",
        "panic",
        "fatal",
    )

    evidence_lines = [
        line.strip()
        for line in combined_logs.splitlines()
        if any(keyword in line.lower() for keyword in error_keywords)
    ]

    for line in evidence_lines[:5]:
        findings.append(f"Application log evidence: {line[:300]}")

    # 3. Inspect Kubernetes warning events.
    warning_messages = []

    for event in pod_details.get("recent_events", []):
        if event.get("type") == "Warning":
            message = event.get("message", "")
            reason = event.get("reason", "")

            warning_messages.append(message)

            findings.append(
                f"Kubernetes warning event ({reason}): {message}"
            )

    all_messages = " ".join(
        container_messages + warning_messages + [combined_logs]
    ).lower()

    # 4. Inspect Prometheus restart metrics.
    restart_metric = prometheus_metrics.get("pod_restarts", {})
    prometheus_restart_count = None

    if restart_metric.get("status") == "success":
        results = restart_metric.get("results", [])

        if results:
            prometheus_restart_count = sum(
                int(float(item.get("value", [None, "0"])[1]))
                for item in results
            )

            findings.append(
                f"Prometheus reports {prometheus_restart_count} total restart(s)."
            )

            if prometheus_restart_count != restart_count:
                findings.append(
                    "Kubernetes and Prometheus restart counts differ. "
                    "Check metric freshness and container status."
                )
      # 4.5. Inspect Prometheus pod readiness metrics.
    readiness_metric = prometheus_metrics.get("pod_ready", {})

    if readiness_metric.get("status") == "success":
        readiness_results = readiness_metric.get("results", [])

        if readiness_results:
            readiness_values = []

            for item in readiness_results:
                try:
                    value = float(item.get("value", [None, "0"])[1])
                    readiness_values.append(value)
                except (TypeError, ValueError, IndexError):
                    continue

            if readiness_values:
                if all(value >= 1 for value in readiness_values):
                    findings.append(
                        "Prometheus reports that the pod is Ready."
                    )
                else:
                    findings.append(
                        "Prometheus reports that the pod is Not Ready."
                    )
            else:
                findings.append(
                    "Prometheus readiness metric returned invalid values."
                )
        else:
            findings.append(
                "Prometheus returned no pod readiness data."
            )
    else:
        findings.append(
            "Prometheus pod readiness metric is unavailable."
        )

    # 5. Diagnose the most likely cause using evidence priority.

    if "OOMKilled" in container_reasons:
        status = "active"
        probable_cause = (
            "The container was terminated because it exceeded its memory "
            "limit. Investigate memory consumption, container memory limits "
            "and possible application memory leaks."
        )

    elif (
        "RunContainerError" in container_reasons
        or "CreateContainerError" in container_reasons
        or "StartError" in container_reasons
        or "oci runtime create failed" in all_messages
    ):
        status = "active"

        if "c:/program files/git/" in all_messages:
            probable_cause = (
                "Container startup failed because Git Bash converted "
                "the Linux container executable path into a Windows path. "
                "Use MSYS_NO_PATHCONV=1 when executing kubectl commands "
                "from Git Bash."
            )
        else:
            probable_cause = (
                "Container failed during startup or runtime creation. "
                "Inspect Kubernetes warning events, container command, "
                "image configuration and container runtime errors."
            )

    elif (
        "CrashLoopBackOff" in container_reasons
        or any(
            event.get("reason") == "BackOff"
            for event in pod_details.get("recent_events", [])
        )
    ):
        status = "active"

        # Specific evidence from the deliberately failing test application.
        if "simulated application failure" in all_messages:
            probable_cause = (
                "Application failure confirmed by the previous container logs. "
                "The application started, then logged 'simulated application "
                "failure' and exited with code 1. Kubernetes repeatedly "
                "restarted the failed container, resulting in CrashLoopBackOff. "
                "This is an application/process failure, not evidence of a "
                "database or worker-node failure."
            )

        elif any(code != 0 for code in exit_codes) and evidence_lines:
            probable_cause = (
                "The container process exited unsuccessfully and its previous "
                "logs contain error-related messages. This indicates a likely "
                "application-level failure. Review the logged errors and the "
                "application startup or execution path to identify the exact "
                "underlying defect."
            )

        elif any(code != 0 for code in exit_codes):
            probable_cause = (
                "The container process exited with a non-zero exit code and "
                "Kubernetes is repeatedly restarting it. This indicates a "
                "process or application failure, but the available logs do "
                "not yet identify the exact cause."
            )

        else:
            probable_cause = (
                "Container is repeatedly failing and Kubernetes is backing "
                "off restart attempts. Inspect previous container logs, "
                "termination reasons, application exceptions and events."
            )

    elif restart_count > 0:
        status = "evidence_found"
        probable_cause = (
            "The pod has recorded container restarts. Investigate previous "
            "logs, termination reasons and Kubernetes events."
        )

    else:
        status = "no_current_crash_evidence"
        probable_cause = (
            "No container restarts or current crash reasons were found "
            "in the available Kubernetes evidence."
        )

    return {
        "status": status,
        "probable_cause": probable_cause,
        "kubernetes_restart_count": restart_count,
        "prometheus_restart_count": prometheus_restart_count,
        "findings": findings,
    }
