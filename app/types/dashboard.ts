export type Ecosystem = "npm" | "pypi";

export interface GithubSession {
  id: number;
  login: string;
  name: string;
  avatarUrl: string;
}

export interface DependencyNode {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  children?: DependencyNode[];
}

export interface Repository {
  id: string;
  name: string;
  visibility: "public" | "private";
  lastPush: string;
  riskScore: number;
  ecosystems: Ecosystem[];
  dependencies: DependencyNode[];
}

export type StaticAnalysisStatus =
  | "idle"
  | "running"
  | "clean"
  | "warning"
  | "critical"
  | "empty";

export interface StaticAnalysisResult {
  status: StaticAnalysisStatus;
  summary: string;
  modelConfidence?: number;
  suspiciousCalls?: string[];
}

export interface DynamicAnalysisReport {
  vmStatus: "idle" | "spawning" | "running" | "complete";
  notes: string;
  suspiciousCalls: string[];
}

export interface QueuedDependencyChange {
  id: string;
  packageName: string;
  version: string;
  ecosystem: Ecosystem;
  repositoryId: string;
}
