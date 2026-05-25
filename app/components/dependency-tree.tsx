"use client";

import { memo, useCallback, useEffect, useMemo, useState } from "react";
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
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { DependencyNode, Ecosystem } from "@/app/types/dashboard";
import { createCacheKey, getCachedValue, hashString, setCachedValue } from "@/app/lib/browser-cache";

interface DependencyTreeProps {
  nodes: DependencyNode[];
  ecosystem: Ecosystem;
  scanResultsMap?: Record<string, ScanResultMapEntry>;
  selectedPackageLabels?: string[];
  selectionEnabled?: boolean;
  onPackageToggleSelect?: (packageLabel: string) => void;
  onNodeFeatureDetail?: (label: string, features: Record<string, number> | null) => void;
}

type ScanResultMapEntry = {
  malware_status?: string;
  malware_score?: number | null;
  static_features?: Record<string, number> | null;
};

type GraphNodeData = {
  label: string;
  malwareStatus: string;
  malwareScore: number | null;
  compact: boolean;
  hasChildren: boolean;
  expanded: boolean;
  hiddenChildrenCount: number;
  selected: boolean;
  staticFeatures: Record<string, number> | null;
};

type GraphNodeRecord = {
  id: string;
  label: string;
  childrenIds: string[];
};

type GraphIndex = {
  rootIds: string[];
  nodeMap: Map<string, GraphNodeRecord>;
  totalNodes: number;
};

const LARGE_GRAPH_NODE_THRESHOLD = 80;
const NODE_SIZE = {
  full: { width: 420, height: 138 },
  compact: { width: 300, height: 108 },
} as const;
const GRAPH_INDEX_CACHE_TTL_MS = 1000 * 60 * 60;
const GRAPH_LAYOUT_CACHE_TTL_MS = 1000 * 60 * 60;
const GRAPH_CACHE_MAX_BYTES = 1_500_000;

type GraphIndexSnapshot = {
  rootIds: string[];
  records: Array<GraphNodeRecord>;
  totalNodes: number;
};

type GraphLayoutSnapshot = {
  nodes: Node<GraphNodeData>[];
  edges: Edge[];
};

function buildTreeSignature(tree: DependencyNode[]): string {
  const parts: string[] = [];

  const walk = (node: DependencyNode) => {
    parts.push(`${node.name}@${node.version}`);
    const children = node.children ?? [];
    parts.push(`[${children.length}]`);
    children.forEach(walk);
    parts.push(";");
  };

  tree.forEach(walk);
  return hashString(parts.join("|"));
}

function buildScanSignature(scanResultsMap: Record<string, ScanResultMapEntry>): string {
  const parts = Object.keys(scanResultsMap)
    .sort()
    .map((key) => {
      const entry = scanResultsMap[key] ?? {};
      return `${key}:${entry.malware_status ?? "unknown"}:${entry.malware_score ?? "null"}`;
    });

  return hashString(parts.join("|"));
}

function buildExpandedSignature(expandedNodeIds: Set<string>) {
  return Array.from(expandedNodeIds).sort().join("|");
}

function serializeGraphIndex(index: GraphIndex): GraphIndexSnapshot {
  return {
    rootIds: index.rootIds,
    totalNodes: index.totalNodes,
    records: Array.from(index.nodeMap.values()),
  };
}

function restoreGraphIndex(snapshot: GraphIndexSnapshot): GraphIndex {
  return {
    rootIds: snapshot.rootIds,
    totalNodes: snapshot.totalNodes,
    nodeMap: new Map(snapshot.records.map((record) => [record.id, record])),
  };
}

function CustomNodeView({ data }: NodeProps) {
  const nodeData = (data as Partial<GraphNodeData> | undefined) ?? {};
  const label = typeof nodeData.label === "string" ? nodeData.label : "unknown@unknown";
  const splitAt = label.lastIndexOf("@");
  const packageName = splitAt > 0 ? label.slice(0, splitAt) : label;
  const version = splitAt > 0 ? label.slice(splitAt + 1) : "unknown";
  const compact = nodeData.compact === true;
  const hasChildren = nodeData.hasChildren === true;
  const expanded = nodeData.expanded === true;
  const hiddenChildrenCount = typeof nodeData.hiddenChildrenCount === "number" ? nodeData.hiddenChildrenCount : 0;
  const selected = nodeData.selected === true;
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

  const containerClassName = compact
    ? `relative min-w-[280px] rounded-xl border bg-gradient-to-br from-slate-900/95 to-slate-800/90 px-4 py-4 ${appearance.borderClass} ${selected ? "ring-2 ring-cyan-300/80 shadow-[0_0_0_1px_rgba(34,211,238,0.35)]" : ""}`
    : `relative min-w-[400px] rounded-2xl border bg-gradient-to-br from-slate-900/95 to-slate-800/90 px-6 py-5 ${appearance.borderClass} ${appearance.glow} ${selected ? "ring-2 ring-cyan-300/80 shadow-[0_0_0_1px_rgba(34,211,238,0.35)]" : ""}`;

  return (
    <div className={containerClassName}>
      <Handle type="target" position={Position.Top} className="!h-3.5 !w-3.5 !border-cyan-300 !bg-cyan-400" />
      <div className="absolute right-4 top-4">
        <span className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${appearance.badgeClass}`}>
          {appearance.label}
        </span>
      </div>
      {selected ? (
        <div className="absolute bottom-4 right-4 rounded-full border border-cyan-300/50 bg-cyan-500/15 px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-100">
          Selected
        </div>
      ) : null}

      <p className={compact ? "line-clamp-1 text-[18px] font-semibold leading-tight text-slate-100" : "line-clamp-1 text-[22px] font-semibold leading-tight text-slate-100"}>
        {packageName}
      </p>
      <p className={compact ? "mt-1 text-[15px] font-medium tracking-wide text-cyan-200/90" : "mt-2 text-[18px] font-medium tracking-wide text-cyan-200/90"}>
        v{version}
      </p>
      {malwareScore !== null ? (
        <p className={compact ? "mt-1 text-[10px] font-medium uppercase tracking-[0.14em] text-slate-300" : "mt-2 text-xs font-medium uppercase tracking-[0.14em] text-slate-300"}>
          Score {(malwareScore * 100).toFixed(1)}%
        </p>
      ) : null}

      {compact && hasChildren ? (
        <div className="mt-3 flex items-center justify-between gap-3 text-[10px] uppercase tracking-[0.16em] text-slate-400">
          <span>{expanded ? "Expanded" : `Click to expand ${hiddenChildrenCount} child${hiddenChildrenCount === 1 ? "" : "ren"}`}</span>
        </div>
      ) : null}

      <Handle type="source" position={Position.Bottom} className="!h-3.5 !w-3.5 !border-cyan-300 !bg-cyan-400" />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  custom: memo(CustomNodeView),
};

function buildGraphIndex(tree: DependencyNode[]): GraphIndex {
  const nodeMap = new Map<string, GraphNodeRecord>();
  const rootIds: string[] = [];
  let totalNodes = 0;

  const walk = (node: DependencyNode, parentId: string | undefined, path: string) => {
    totalNodes += 1;
    const id = `${path}:${node.name}@${node.version}`;
    const childrenIds: string[] = [];

    nodeMap.set(id, {
      id,
      label: `${node.name}@${node.version}`,
      childrenIds,
    });

    if (parentId) {
      const parentRecord = nodeMap.get(parentId);
      if (parentRecord) {
        parentRecord.childrenIds.push(id);
      }
    } else {
      rootIds.push(id);
    }

    (node.children ?? []).forEach((child, index) => {
      walk(child, id, `${id}:${index}`);
    });
  };

  tree.forEach((rootNode, index) => {
    walk(rootNode, undefined, `root-${index}`);
  });

  return { rootIds, nodeMap, totalNodes };
}

function materializeVisibleGraph(
  index: GraphIndex,
  scanResultsMap: Record<string, ScanResultMapEntry>,
  expandedNodeIds: Set<string>,
  compactMode: boolean,
) {
  const nodes: Node<GraphNodeData>[] = [];
  const edges: Edge[] = [];

  const visit = (nodeId: string, parentId?: string) => {
    const record = index.nodeMap.get(nodeId);
    if (!record) {
      return;
    }

    const splitAt = record.label.lastIndexOf("@");
    const packageName = splitAt > 0 ? record.label.slice(0, splitAt) : record.label;
    const version = splitAt > 0 ? record.label.slice(splitAt + 1) : "unknown";
    const match = scanResultsMap[record.label];
    const hasChildren = record.childrenIds.length > 0;
    const expanded = !compactMode || expandedNodeIds.has(nodeId);

    nodes.push({
      id: nodeId,
      type: "custom",
      position: { x: 0, y: 0 },
      data: {
        label: `${packageName}@${version}`,
        malwareStatus: match?.malware_status ?? "unknown",
        malwareScore: match?.malware_score ?? null,
        compact: compactMode,
        hasChildren,
        expanded: compactMode ? expanded : true,
        hiddenChildrenCount: compactMode && !expanded ? record.childrenIds.length : 0,
        selected: false,
        staticFeatures: match?.static_features ?? null,
      },
    });

    if (parentId) {
      edges.push({
        id: `${parentId}->${nodeId}`,
        source: parentId,
        target: nodeId,
        type: "default",
        animated: !compactMode,
        style: { stroke: "#14b8a6", strokeWidth: 2 },
      });
    }

    if (!compactMode || expanded) {
      record.childrenIds.forEach((childId) => {
        visit(childId, nodeId);
      });
    }
  };

  index.rootIds.forEach((rootId) => visit(rootId));

  return { nodes, edges };
}

function layoutElements(nodes: Node<GraphNodeData>[], edges: Edge[], compactMode: boolean) {
  const nodeSize = compactMode ? NODE_SIZE.compact : NODE_SIZE.full;
  const graph = new dagre.graphlib.Graph();
  graph.setDefaultEdgeLabel(() => ({}));
  graph.setGraph({
    rankdir: "TB",
    nodesep: compactMode ? 60 : 90,
    ranksep: compactMode ? 160 : 260,
    marginx: compactMode ? 16 : 24,
    marginy: compactMode ? 16 : 24,
  });

  nodes.forEach((node) => {
    graph.setNode(node.id, { width: nodeSize.width, height: nodeSize.height });
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
        x: position.x - nodeSize.width / 2,
        y: position.y - nodeSize.height / 2,
      },
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top,
    };
  });

  return { nodes: layoutedNodes, edges };
}

export function DependencyTree({
  nodes,
  ecosystem,
  scanResultsMap = {},
  selectedPackageLabels = [],
  selectionEnabled = false,
  onPackageToggleSelect,
  onNodeFeatureDetail,
}: DependencyTreeProps) {
  const selectedLabelSet = useMemo(() => new Set(selectedPackageLabels), [selectedPackageLabels]);
  const filtered = useMemo(() => nodes.filter((node) => node.ecosystem === ecosystem), [nodes, ecosystem]);
  const treeSignature = useMemo(() => buildTreeSignature(filtered), [filtered]);
  const scanSignature = useMemo(() => buildScanSignature(scanResultsMap), [scanResultsMap]);
  const graphIndexCacheKey = useMemo(() => createCacheKey("dependency-graph-index", ecosystem, treeSignature), [ecosystem, treeSignature]);
  const cachedGraphIndex = useMemo(() => getCachedValue<GraphIndexSnapshot>(graphIndexCacheKey), [graphIndexCacheKey]);
  const graphIndex = useMemo(
    () => (cachedGraphIndex ? restoreGraphIndex(cachedGraphIndex) : buildGraphIndex(filtered)),
    [cachedGraphIndex, filtered],
  );
  const largeGraphMode = graphIndex.totalNodes >= LARGE_GRAPH_NODE_THRESHOLD;
  const defaultExpandedNodeIds = useMemo(
    () => (largeGraphMode && ecosystem === "pypi" ? new Set(graphIndex.rootIds) : new Set<string>()),
    [graphIndex.rootIds, ecosystem, largeGraphMode],
  );
  const [expandedNodeIds, setExpandedNodeIds] = useState<Set<string>>(() => new Set());
  const [reactFlowInstance, setReactFlowInstance] = useState<Parameters<NonNullable<React.ComponentProps<typeof ReactFlow>["onInit"]>>[0] | null>(null);
  const [flowNodes, setFlowNodes, onNodesChange] = useNodesState<Node>([]);
  const [flowEdges, setFlowEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [isInteractive, setIsInteractive] = useState(!largeGraphMode);

  useEffect(() => {
    if (!cachedGraphIndex) {
      setCachedValue(graphIndexCacheKey, serializeGraphIndex(graphIndex), {
        ttlMs: GRAPH_INDEX_CACHE_TTL_MS,
        scope: "both",
        maxPersistentSizeBytes: GRAPH_CACHE_MAX_BYTES,
      });
    }
  }, [cachedGraphIndex, graphIndex, graphIndexCacheKey]);

  useEffect(() => {
    setExpandedNodeIds(defaultExpandedNodeIds);
  }, [defaultExpandedNodeIds]);

  useEffect(() => {
    setIsInteractive(!largeGraphMode);
  }, [largeGraphMode]);

  const layoutCacheKey = useMemo(
    () => createCacheKey("dependency-graph-layout", ecosystem, treeSignature, scanSignature, largeGraphMode, buildExpandedSignature(expandedNodeIds)),
    [ecosystem, treeSignature, scanSignature, largeGraphMode, expandedNodeIds],
  );
  const cachedLayout = useMemo(() => getCachedValue<GraphLayoutSnapshot>(layoutCacheKey), [layoutCacheKey]);
  const layoutedGraph = useMemo(() => {
    if (cachedLayout) {
      return cachedLayout;
    }

    const visibleGraph = materializeVisibleGraph(graphIndex, scanResultsMap, expandedNodeIds, largeGraphMode);
    return layoutElements(visibleGraph.nodes, visibleGraph.edges, largeGraphMode);
  }, [cachedLayout, graphIndex, scanResultsMap, expandedNodeIds, largeGraphMode]);

  useEffect(() => {
    if (!cachedLayout) {
      setCachedValue(layoutCacheKey, layoutedGraph, {
        ttlMs: GRAPH_LAYOUT_CACHE_TTL_MS,
        scope: "both",
        maxPersistentSizeBytes: GRAPH_CACHE_MAX_BYTES,
      });
    }
  }, [cachedLayout, layoutedGraph, layoutCacheKey]);

  useEffect(() => {
    setFlowNodes(
      layoutedGraph.nodes.map((node) => ({
        ...node,
        data: {
          ...node.data,
          selected: selectedLabelSet.has(typeof node.data.label === "string" ? node.data.label : ""),
        },
      })),
    );
    setFlowEdges(layoutedGraph.edges);
  }, [layoutedGraph, selectedLabelSet, setFlowNodes, setFlowEdges]);

  useEffect(() => {
    if (!reactFlowInstance) {
      return;
    }

    reactFlowInstance.fitView({
      padding: largeGraphMode ? 0.12 : 0.2,
      includeHiddenNodes: false,
    });
  }, [reactFlowInstance, layoutedGraph.nodes, layoutedGraph.edges, largeGraphMode]);

  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      const nodeData = (node.data as Partial<GraphNodeData> | undefined) ?? {};

      if (selectionEnabled && typeof nodeData.label === "string" && onPackageToggleSelect) {
        onPackageToggleSelect(nodeData.label);
      }

      if (onNodeFeatureDetail && typeof nodeData.label === "string") {
        onNodeFeatureDetail(nodeData.label, nodeData.staticFeatures ?? null);
      }

      if (!largeGraphMode || nodeData.hasChildren !== true) {
        return;
      }

      setExpandedNodeIds((current) => {
        const next = new Set(current);

        if (next.has(node.id)) {
          next.delete(node.id);
        } else {
          next.add(node.id);
        }

        return next;
      });
    },
    [largeGraphMode, onNodeFeatureDetail, onPackageToggleSelect, selectionEnabled],
  );

  return (
    <div className="relative h-full w-full overflow-hidden bg-[radial-gradient(circle_at_10%_10%,rgba(15,23,42,0.96),rgba(2,6,23,0.98)_48%)]">
      <ReactFlow
        onInit={setReactFlowInstance}
        nodes={flowNodes}
        edges={flowEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        nodeTypes={nodeTypes}
        panOnScroll={true}
        panOnDrag={true}
        zoomOnScroll={true}
        nodesDraggable={isInteractive}
        elementsSelectable={isInteractive}
        nodesConnectable={isInteractive}
        zoomOnDoubleClick={true}
        onlyRenderVisibleElements={largeGraphMode}
        fitView={true}
        fitViewOptions={{
          padding: largeGraphMode ? 0.12 : 0.2,
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
          onInteractiveChange={(interactiveStatus) => setIsInteractive(interactiveStatus)}
          className="!border !border-teal-400/60 !bg-slate-900/95 !text-teal-200 !shadow-[0_0_24px_-12px_rgba(20,184,166,0.95)] [&_button]:!bg-slate-800/95 [&_button]:!text-teal-100 [&_button:hover]:!bg-teal-500/25 [&_button]:!border-b [&_button]:!border-teal-400/40"
        />
      </ReactFlow>
    </div>
  );
}
