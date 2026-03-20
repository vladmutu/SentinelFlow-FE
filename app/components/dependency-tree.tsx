"use client";

import { useEffect, useMemo, useState } from "react";
import dagre from "dagre";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  applyEdgeChanges,
  applyNodeChanges,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeProps,
  type NodeTypes,
  type NodeChange,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { DependencyNode, Ecosystem } from "@/app/types/dashboard";

interface DependencyTreeProps {
  nodes: DependencyNode[];
  ecosystem: Ecosystem;
}

const NODE_WIDTH = 420;
const NODE_HEIGHT = 138;

function CustomNode({ data }: NodeProps) {
  const label = (data as { label?: unknown } | undefined)?.label;
  const rawLabel = typeof label === "string" ? label : "unknown@unknown";
  const splitAt = rawLabel.lastIndexOf("@");
  const packageName = splitAt > 0 ? rawLabel.slice(0, splitAt) : rawLabel;
  const version = splitAt > 0 ? rawLabel.slice(splitAt + 1) : "unknown";

  return (
    <div className="relative min-w-[400px] rounded-2xl border border-cyan-300/45 bg-gradient-to-br from-slate-900/95 to-slate-800/90 px-6 py-5 shadow-[0_0_34px_-10px_rgba(45,212,191,0.95)]">
      <Handle type="target" position={Position.Top} className="!h-3.5 !w-3.5 !border-cyan-300 !bg-cyan-400" />
      <p className="line-clamp-1 text-[22px] font-semibold leading-tight text-slate-100">{packageName}</p>
      <p className="mt-2 text-[18px] font-medium tracking-wide text-cyan-200/90">v{version}</p>
      <Handle type="source" position={Position.Bottom} className="!h-3.5 !w-3.5 !border-cyan-300 !bg-cyan-400" />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  custom: CustomNode,
};

function toGraphElements(tree: DependencyNode[]) {
  const initialNodes: Node[] = [];
  const initialEdges: Edge[] = [];

  const walk = (node: DependencyNode, parentId?: string, path = "root") => {
    const nodeId = `${path}:${node.name}@${node.version}`;

    initialNodes.push({
      id: nodeId,
      type: "custom",
      position: { x: 0, y: 0 },
      data: { label: `${node.name}@${node.version}` },
    });

    if (parentId) {
      initialEdges.push({
        id: `${parentId}->${nodeId}`,
        source: parentId,
        target: nodeId,
        type: "default",
        animated: true,
        style: { stroke: "#14b8a6", strokeWidth: 2 },
      });
    }

    (node.children ?? []).forEach((child, index) => {
      walk(child, nodeId, `${nodeId}:${index}`);
    });
  };

  tree.forEach((rootNode, index) => {
    walk(rootNode, undefined, `root-${index}`);
  });

  return { initialNodes, initialEdges };
}

function getLayoutedElements(nodes: Node[], edges: Edge[]) {
  const graph = new dagre.graphlib.Graph();
  graph.setDefaultEdgeLabel(() => ({}));
  graph.setGraph({
    rankdir: "TB",
    nodesep: 70,
    ranksep: 180,
    marginx: 24,
    marginy: 24,
  });

  nodes.forEach((node) => {
    graph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });

  edges.forEach((edge) => {
    graph.setEdge(edge.source, edge.target);
  });

  dagre.layout(graph);

  const layoutedNodes = nodes.map((node) => {
    const position = graph.node(node.id);
    return {
      ...node,
      position: {
        x: position.x - NODE_WIDTH / 2,
        y: position.y - NODE_HEIGHT / 2,
      },
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top,
    };
  });

  return { nodes: layoutedNodes, edges };
}

export function DependencyTree({ nodes, ecosystem }: DependencyTreeProps) {
  const filtered = useMemo(() => nodes.filter((node) => node.ecosystem === ecosystem), [nodes, ecosystem]);

  const { layoutedNodes, layoutedEdges } = useMemo(() => {
    const { initialNodes, initialEdges } = toGraphElements(filtered);
    const { nodes: graphNodes, edges: graphEdges } = getLayoutedElements(initialNodes, initialEdges);
    return { layoutedNodes: graphNodes, layoutedEdges: graphEdges };
  }, [filtered]);

  const [flowNodes, setFlowNodes] = useState<Node[]>(layoutedNodes);
  const [flowEdges, setFlowEdges] = useState<Edge[]>(layoutedEdges);
  const [reactFlowInstance, setReactFlowInstance] = useState<
    Parameters<NonNullable<React.ComponentProps<typeof ReactFlow>["onInit"]>>[0] | null
  >(null);

  useEffect(() => {
    setFlowNodes(layoutedNodes);
    setFlowEdges(layoutedEdges);
  }, [layoutedNodes, layoutedEdges]);

  useEffect(() => {
    if (!reactFlowInstance || layoutedNodes.length === 0) {
      return;
    }

    reactFlowInstance.fitView({
      padding: 0.2,
      duration: 350,
      includeHiddenNodes: false,
    });
  }, [layoutedNodes, reactFlowInstance]);

  const onNodesChange = (changes: NodeChange[]) => {
    setFlowNodes((current) => applyNodeChanges(changes, current));
  };

  const onEdgesChange = (changes: EdgeChange[]) => {
    setFlowEdges((current) => applyEdgeChanges(changes, current));
  };

  if (filtered.length === 0) {
    return (
      <p className="text-sm text-slate-300">
        No {ecosystem.toUpperCase()} dependencies were detected for this repository.
      </p>
    );
  }

  return (
    <div className="h-full w-full overflow-hidden bg-[radial-gradient(circle_at_10%_10%,rgba(15,23,42,0.96),rgba(2,6,23,0.98)_48%)]">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        onInit={setReactFlowInstance}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        panOnScroll={true}
        panOnDrag={true}
        zoomOnScroll={true}
        nodesDraggable={true}
        elementsSelectable={true}
        zoomOnDoubleClick={true}
        fitView={false}
        minZoom={0.2}
        maxZoom={1.6}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="rgba(51, 65, 85, 0.45)" gap={26} size={1.2} variant={BackgroundVariant.Dots} />
        <MiniMap
          pannable
          zoomable
          className="!border !border-slate-700/90 !bg-slate-900/90"
          maskColor="rgba(2, 6, 23, 0.55)"
          nodeColor="rgba(34, 211, 238, 0.75)"
        />
        <Controls
          showInteractive={true}
          className="!border !border-teal-400/60 !bg-slate-900/95 !text-teal-200 !shadow-[0_0_24px_-12px_rgba(20,184,166,0.95)] [&_button]:!bg-slate-800/95 [&_button]:!text-teal-100 [&_button:hover]:!bg-teal-500/25 [&_button]:!border-b [&_button]:!border-teal-400/40"
        />
      </ReactFlow>
    </div>
  );
}
