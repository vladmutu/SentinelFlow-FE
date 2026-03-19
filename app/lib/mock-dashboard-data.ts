import {
  DynamicAnalysisReport,
  Repository,
  StaticAnalysisResult,
} from "@/app/types/dashboard";

export const apiContract = {
  connectGithub: "POST /api/github/connect",
  listRepositories: "GET /api/github/repos",
  dependencyTree: "GET /api/repos/:repoId/dependencies?ecosystem=npm|pypi",
  addDependency: "POST /api/repos/:repoId/dependencies",
  staticAnalysis: "POST /api/repos/:repoId/analyze/static",
  dynamicAnalysis: "POST /api/repos/:repoId/analyze/dynamic",
};

export const initialRepositories: Repository[] = [
  {
    id: "repo-1",
    name: "commerce-portal",
    visibility: "private",
    lastPush: "2026-03-12",
    riskScore: 31,
    ecosystems: ["npm"],
    dependencies: [
      {
        name: "next",
        version: "16.2.0",
        ecosystem: "npm",
        children: [
          {
            name: "react",
            version: "19.2.4",
            ecosystem: "npm",
            children: [{ name: "scheduler", version: "0.27.0", ecosystem: "npm" }],
          },
        ],
      },
      { name: "zod", version: "4.1.0", ecosystem: "npm" },
      { name: "jsonwebtoken", version: "9.0.2", ecosystem: "npm" },
    ],
  },
  {
    id: "repo-2",
    name: "threat-intel-engine",
    visibility: "private",
    lastPush: "2026-03-17",
    riskScore: 86,
    ecosystems: ["pypi"],
    dependencies: [
      {
        name: "fastapi",
        version: "0.116.0",
        ecosystem: "pypi",
        children: [{ name: "pydantic", version: "2.11.5", ecosystem: "pypi" }],
      },
      { name: "scikit-learn", version: "1.7.0", ecosystem: "pypi" },
      { name: "uvicorn", version: "0.35.0", ecosystem: "pypi" },
    ],
  },
  {
    id: "repo-3",
    name: "hybrid-monitor",
    visibility: "public",
    lastPush: "2026-03-18",
    riskScore: 62,
    ecosystems: ["npm", "pypi"],
    dependencies: [
      {
        name: "electron",
        version: "37.2.0",
        ecosystem: "npm",
        children: [
          { name: "@electron/get", version: "2.0.2", ecosystem: "npm" },
          { name: "ws", version: "8.18.3", ecosystem: "npm" },
        ],
      },
      {
        name: "requests",
        version: "2.32.4",
        ecosystem: "pypi",
        children: [{ name: "urllib3", version: "2.4.0", ecosystem: "pypi" }],
      },
    ],
  },
];

export const idleStaticAnalysis: StaticAnalysisResult = {
  status: "idle",
  summary: "No static analysis has been run yet.",
};

export const idleDynamicAnalysis: DynamicAnalysisReport = {
  vmStatus: "idle",
  notes: "VM sandbox has not been started.",
  suspiciousCalls: [],
};
