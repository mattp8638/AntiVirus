"""Correlation utilities for linking events to findings."""
from __future__ import annotations

from .models import CorrelationEdge, CorrelationGraph, CorrelationNode, NormalisedEvent


def build_correlation_graph(event: NormalisedEvent) -> CorrelationGraph:
    """Build a minimal correlation graph from a single event."""
    nodes: list[CorrelationNode] = []
    edges: list[CorrelationEdge] = []

    event_node = CorrelationNode(
        node_id=event.event_id,
        node_type="event",
        label=event.event_type,
    )
    nodes.append(event_node)

    asset_node = CorrelationNode(
        node_id=f"asset:{event.asset_id}",
        node_type="asset",
        label=event.asset_id,
    )
    identity_node = CorrelationNode(
        node_id=f"identity:{event.identity_id}",
        node_type="identity",
        label=event.identity_id,
    )
    nodes.extend([asset_node, identity_node])

    edges.extend(
        [
            CorrelationEdge(source=event_node.node_id, target=asset_node.node_id, relationship="occurred_on"),
            CorrelationEdge(source=event_node.node_id, target=identity_node.node_id, relationship="initiated_by"),
        ]
    )

    if event.process_lineage and event.process_lineage.process_name:
        process_node = CorrelationNode(
            node_id=f"process:{event.process_lineage.process_name}",
            node_type="process",
            label=event.process_lineage.process_name,
        )
        nodes.append(process_node)
        edges.append(
            CorrelationEdge(
                source=event_node.node_id,
                target=process_node.node_id,
                relationship="spawned",
            )
        )

    if event.network_flow and event.network_flow.destination:
        network_node = CorrelationNode(
            node_id=f"network:{event.network_flow.destination}",
            node_type="network",
            label=event.network_flow.destination,
        )
        nodes.append(network_node)
        edges.append(
            CorrelationEdge(
                source=event_node.node_id,
                target=network_node.node_id,
                relationship="communicated_with",
            )
        )

    return CorrelationGraph(nodes=nodes, edges=edges)
