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
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { DependencyNode, Ecosystem } from "@/app/types/dashboard";

interface DependencyTreeProps {
  nodes: DependencyNode[];
  ecosystem: Ecosystem;
  scanResultsMap?: Record<string, ScanResultMapEntry>;
}

type ScanResultMapEntry = {
  malware_status?: string;
  malware_score?: number | null;
};

const NODE_WIDTH = 420;
const NODE_HEIGHT = 138;

function CustomNode({ data }: NodeProps) {
  const nodeData = (data as { label?: unknown; malwareStatus?: unknown; malwareScore?: unknown } | undefined) ?? {};
  const label = nodeData.label;
  const rawLabel = typeof label === "string" ? label : "unknown@unknown";
  const splitAt = rawLabel.lastIndexOf("@");
  const packageName = splitAt > 0 ? rawLabel.slice(0, splitAt) : rawLabel;
  const version = splitAt > 0 ? rawLabel.slice(splitAt + 1) : "unknown";
  const malwareStatus = typeof nodeData.malwareStatus === "string" ? nodeData.malwareStatus.toLowerCase() : "unknown";
  const malwareScore = typeof nodeData.malwareScore === "number" ? nodeData.malwareScore : null;

  const appearance =
    malwareStatus === "malicious"
      ? {
          borderClass: "border-rose-300/65",
          glow: "shadow-[0_0_36px_-10px_rgba(251,113,133,0.92)]",
          badgeClass: "border border-rose-300/50 bg-rose-500/20 text-rose-100",
          label: "Malicious",
        }
      : malwareStatus === "suspicious"
        ? {
            borderClass: "border-amber-300/65",
            glow: "shadow-[0_0_36px_-10px_rgba(251,191,36,0.82)]",
            badgeClass: "border border-amber-300/50 bg-amber-500/20 text-amber-100",
            label: "Suspicious",
          }
        : malwareStatus === "clean" || malwareStatus === "benign"
          ? {
              borderClass: "border-emerald-300/55",
              glow: "shadow-[0_0_32px_-10px_rgba(52,211,153,0.82)]",
              badgeClass: "border border-emerald-300/40 bg-emerald-500/15 text-emerald-100",
              label: "Clean",
            }
          : {
              borderClass: "border-cyan-300/45",
              glow: "shadow-[0_0_34px_-10px_rgba(45,212,191,0.95)]",
              badgeClass: "border border-slate-400/35 bg-slate-500/15 text-slate-100",
              label: "Not Scanned",
            };

  return (
    <div
      className={`relative min-w-[400px] rounded-2xl border bg-gradient-to-br from-slate-900/95 to-slate-800/90 px-6 py-5 ${appearance.borderClass} ${appearance.glow}`}
    >
      <Handle type="target" position={Position.Top} className="!h-3.5 !w-3.5 !border-cyan-300 !bg-cyan-400" />
      <div className="absolute right-4 top-4">
        <span className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${appearance.badgeClass}`}>
          {appearance.label}
        </span>
      </div>
      <p className="line-clamp-1 text-[22px] font-semibold leading-tight text-slate-100">{packageName}</p>
      <p className="mt-2 text-[18px] font-medium tracking-wide text-cyan-200/90">v{version}</p>
      {malwareScore !== null ? (
        <p className="mt-2 text-xs font-medium uppercase tracking-[0.14em] text-slate-300">Score {(malwareScore * 100).toFixed(1)}%</p>
      ) : null}
      <Handle type="source" position={Position.Bottom} className="!h-3.5 !w-3.5 !border-cyan-300 !bg-cyan-400" />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  custom: CustomNode,
};

function toGraphElements(tree: DependencyNode[], scanResultsMap: Record<string, ScanResultMapEntry>) {
  const initialNodes: Node[] = [];
  const initialEdges: Edge[] = [];

  const walk = (node: DependencyNode, parentId?: string, path = "root") => {
    const nodeId = `${path}:${node.name}@${node.version}`;

    initialNodes.push({
      id: nodeId,
      type: "custom",
      position: { x: 0, y: 0 },
      data: {
        label: `${node.name}@${node.version}`,
        malwareStatus: scanResultsMap[`${node.name}@${node.version}`]?.malware_status ?? "unknown",
        malwareScore: scanResultsMap[`${node.name}@${node.version}`]?.malware_score ?? null,
      },
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

export function DependencyTree({ nodes, ecosystem, scanResultsMap = {} }: DependencyTreeProps) {
  const filtered = useMemo(() => nodes.filter((node) => node.ecosystem === ecosystem), [nodes, ecosystem]);

  const { layoutedNodes, layoutedEdges } = useMemo(() => {
    const { initialNodes, initialEdges } = toGraphElements(filtered, scanResultsMap);
    const { nodes: graphNodes, edges: graphEdges } = getLayoutedElements(initialNodes, initialEdges);
    return { layoutedNodes: graphNodes, layoutedEdges: graphEdges };
  }, [filtered, scanResultsMap]);

  const flowKey = useMemo(
    () => `${ecosystem}:${layoutedNodes.map((node) => node.id).join("|")}:${layoutedEdges.map((edge) => edge.id).join("|")}`,
    [ecosystem, layoutedNodes, layoutedEdges],
  );

  const [reactFlowInstance, setReactFlowInstance] = useState<
    Parameters<NonNullable<React.ComponentProps<typeof ReactFlow>["onInit"]>>[0] | null
  >(null);

  useEffect(() => {
    if (!reactFlowInstance) {
      return;
    }

    reactFlowInstance.setNodes((currentNodes) =>
      currentNodes.map((node) => {
        const label = (node.data as { label?: unknown } | undefined)?.label;
        const packageKey = typeof label === "string" ? label : "";
        const match = scanResultsMap[packageKey];

        return {
          ...node,
          data: {
            ...(node.data as Record<string, unknown>),
            malwareStatus: match?.malware_status ?? "unknown",
            malwareScore: match?.malware_score ?? null,
          },
        };
      }),
    );
  }, [reactFlowInstance, scanResultsMap]);

  return (
    <div className="relative h-full w-full overflow-hidden bg-[radial-gradient(circle_at_10%_10%,rgba(15,23,42,0.96),rgba(2,6,23,0.98)_48%)]">
      <ReactFlow
        key={flowKey}
        defaultNodes={layoutedNodes}
        defaultEdges={layoutedEdges}
        onInit={setReactFlowInstance}
        nodeTypes={nodeTypes}
        panOnScroll={true}
        panOnDrag={true}
        zoomOnScroll={true}
        nodesDraggable={true}
        elementsSelectable={true}
        zoomOnDoubleClick={true}
        fitView={true}
        fitViewOptions={{
          padding: 0.2,
          includeHiddenNodes: false,
        }}
        minZoom={0.2}
        maxZoom={1.6}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="rgba(51, 65, 85, 0.45)" gap={26} size={1.2} variant={BackgroundVariant.Dots} />
        <MiniMap
          pannable
          zoomable
          nodeColor={(node) => {
            const nodeData = (node.data as { malwareStatus?: unknown } | undefined) ?? {};
            const status = typeof nodeData.malwareStatus === "string" ? nodeData.malwareStatus.toLowerCase() : "unknown";

            if (status === "malicious") {
              return "#fb7185";
            }

            if (status === "suspicious") {
              return "#f59e0b";
            }

            if (status === "clean" || status === "benign") {
              return "#34d399";
            }

            return "#22d3ee";
          }}
          className="!border !border-slate-700/90 !bg-slate-900/90"
          bgColor="#020617"
          maskColor="rgba(2, 6, 23, 0.55)"
          maskStrokeColor="#0f172a"
          nodeStrokeColor="#0f172a"
          nodeStrokeWidth={2}
          nodeBorderRadius={8}
        />
        <Controls
          showInteractive={true}
          className="!border !border-teal-400/60 !bg-slate-900/95 !text-teal-200 !shadow-[0_0_24px_-12px_rgba(20,184,166,0.95)] [&_button]:!bg-slate-800/95 [&_button]:!text-teal-100 [&_button:hover]:!bg-teal-500/25 [&_button]:!border-b [&_button]:!border-teal-400/40"
        />
      </ReactFlow>
    </div>
  );
}
