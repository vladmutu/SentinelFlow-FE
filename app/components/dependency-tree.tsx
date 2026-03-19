"use client";

import { DependencyNode, Ecosystem } from "@/app/types/dashboard";

interface DependencyTreeProps {
  nodes: DependencyNode[];
  ecosystem: Ecosystem;
}

function DependencyBranch({
  node,
  depth,
}: {
  node: DependencyNode;
  depth: number;
}) {
  return (
    <li className="space-y-2">
      <div
        className="tree-row"
        style={{ paddingLeft: `${depth * 0.95}rem` }}
      >
        <span className="tree-package">{node.name}</span>
        <span className="tree-version">{node.version}</span>
      </div>
      {node.children && node.children.length > 0 ? (
        <ul className="space-y-1.5">
          {node.children.map((child) => (
            <DependencyBranch
              key={`${node.name}-${child.name}-${child.version}`}
              node={child}
              depth={depth + 1}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function DependencyTree({ nodes, ecosystem }: DependencyTreeProps) {
  const filtered = nodes.filter((node) => node.ecosystem === ecosystem);

  if (filtered.length === 0) {
    return (
      <p className="text-sm text-muted">
        No {ecosystem.toUpperCase()} dependencies were detected for this repository.
      </p>
    );
  }

  return (
    <ul className="space-y-1.5">
      {filtered.map((node) => (
        <DependencyBranch
          key={`${node.name}-${node.version}`}
          node={node}
          depth={0}
        />
      ))}
    </ul>
  );
}
