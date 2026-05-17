# SentinelFlow-FE Implementation Status

## Overview
SentinelFlow-FE is a Next.js 16 frontend for a dependency security dashboard. It supports npm and PyPI ecosystems with dependency tree visualization, security analysis, and dependency management features.

---

## 1. API Utilities & Fetch Helpers

### Location: `app/lib/api/`

#### **dependency-pr.ts** ✅ IMPLEMENTED
- **Package Search**: `searchPackages()` - Queries package registries with pagination (8 items/page)
- **Version Fetching**: `fetchPackageVersions()` - Gets available versions for a package
- **PR Creation**: `createDependencyPr()` - Creates GitHub PRs with dependency updates
- **Error Handling**: `DependencyApiError` class, `mapDependencyApiError()` for user-friendly messages
- **Utility Functions**:
  - `createDependencyIdempotencyKey()` - Generates idempotent request keys
  - `normalizeSearchResponse()` - Validates and sorts search results with typosquat detection
  - `compareSearchResultRelevance()` - Ranking logic considering: levenshtein distance, version availability, typosquat score, downloads, relevance score

**API Endpoints Called**:
```
GET /api/repos/packages/search?ecosystem={npm|pypi}&q={query}&page={int}&limit={int}
GET /api/repos/packages/versions?ecosystem={npm|pypi}&name={packageName}&limit={int}
POST /api/repos/packages/create-pr (inferred)
```

#### **Other API Utilities**:
- `app/lib/browser-cache.ts` ✅ - In-memory + sessionStorage + localStorage caching with TTL
- `app/lib/auth/client-session.ts` ✅ - Token storage helpers
- `app/lib/auth/session.ts` - Server-side session (not yet explored)

### API Routes (Backend Stubs/Placeholders)
- `app/api/auth/github/route.ts` - GitHub OAuth flow
- `app/api/auth/github/callback/route.ts` - OAuth callback
- `app/api/auth/logout/route.ts` - Logout handler
- `app/api/packages/search/` ❌ **EMPTY** - Should implement package search
- `app/api/packages/versions/` ❌ **EMPTY** - Should implement version fetching

---

## 2. TypeScript Types

### Location: `app/types/dashboard.ts` ✅ COMPLETE

```typescript
// Core Types:
- Ecosystem = "npm" | "pypi"
- GithubSession { id, login, name, avatarUrl }
- DependencyNode { name, version, ecosystem, children?: DependencyNode[] }
- Repository { id, name, visibility, lastPush, riskScore, ecosystems[], dependencies[] }

// Analysis Types:
- StaticAnalysisStatus = "idle" | "running" | "clean" | "warning" | "critical" | "empty"
- StaticAnalysisResult { status, summary, modelConfidence, suspiciousCalls[] }
- DynamicAnalysisReport { vmStatus, notes, suspiciousCalls[] }

// Dependency Management Types:
- QueuedDependencyChange { id, packageName, version, ecosystem, repositoryId }
```

### Location: `app/lib/api/dependency-pr.ts` ✅ DEPENDENCY TYPES

```typescript
// Typosquat Detection:
- TyposquatInfo { is_suspected, confidence, levenshtein_distance, edit_distance, normalized_conflict, reasons[] }
- PackageSearchResult { ecosystem, name, version, description, homepage, registry_url, score, monthly_downloads, typosquat }
- PackageSearchResponse { ecosystem, query, page, limit, total, results[], did_you_mean }
- PackageVersionsResponse { name, versions[] }

// PR Creation:
- DependencyDraft { name, version }
- CreateDependencyPrRequest { ecosystem, dependencies[], idempotency_key, branch_name, pr_title, pr_body, updated_package_lock_json, generate_lockfile_server_side }
- CreateDependencyPrResponse { pr_url, pr_number, branch_name, status, message }

// Context & Errors:
- DependencyApiContext { baseUrl, authHeaders }
- DependencyApiError extends Error { status, detail }
```

---

## 3. Dashboard Data Structure

### Mock Data: `app/lib/mock-dashboard-data.ts` ✅

**API Contract** (defined in `apiContract` object):
```
POST /api/github/connect
GET /api/github/repos
GET /api/repos/:repoId/dependencies?ecosystem=npm|pypi
POST /api/repos/:repoId/dependencies
POST /api/repos/:repoId/analyze/static
POST /api/repos/:repoId/analyze/dynamic
```

**Initial Repositories** (3 sample repos):
1. `commerce-portal` (npm, risk: 31)
   - next 16.2.0 → react 19.2.4 → scheduler 0.27.0
   - zod 4.1.0
   - jsonwebtoken 9.0.2

2. `threat-intel-engine` (pypi, risk: 86)
   - fastapi 0.116.0 → pydantic 2.11.5
   - scikit-learn 1.7.0
   - uvicorn 0.35.0

3. `hybrid-monitor` (npm + pypi, risk: 62)
   - electron 37.2.0 → @electron/get 2.0.2, ws 8.18.3
   - requests 2.32.4 → urllib3 2.4.0

**Idle States**:
- `idleStaticAnalysis` - Status: "idle", no analysis run yet
- `idleDynamicAnalysis` - VM status: "idle", no sandbox activity

### Dashboard Repo Page: `app/dashboard/repo/[id]/page.tsx` (Partial)

**Key Data Flows**:
- Cache strategy: Multiple TTLs for different data
  - Dashboard snapshot: 20 mins
  - Dependency tree: 10 mins
  - Scan results: 3 mins
- Session extraction from JWT (username extraction pattern available)
- Scan job polling (job_id, status tracking)

---

## 4. Package Search, Version Picker, Add-Dependency Implementation

### Location: `app/components/add-dependency-panel.tsx` ✅ FULLY IMPLEMENTED

**Component Features**:
- ✅ **Package Search** with pagination and infinite scroll
  - Query debouncing (300ms)
  - Page size: 8 results
  - Typosquat detection with "Did You Mean?" suggestions
  - Levenshtein distance-based spell checking
  - Search state: loading, error, retryable errors, suggestions
  
- ✅ **Version Picking** with lazy loading
  - Version lookup on package selection
  - Version popularity tracking
  - Normalized version formatting (ecosystem-specific: pypi strips `=`, npm takes as-is)

- ✅ **Add Dependency Flow**
  - Multiple package selection
  - Suspicious package warnings (typosquat flagged with confidence scores)
  - Branch name customization
  - PR title and body customization
  - Server-side lockfile generation option
  - Idempotent PR creation
  - Success/error feedback

**Component State**:
- `ecosystem` - Selected ecosystem (npm/pypi)
- `query` - Search input
- `results` - Package search results
- `selection` - Selected dependencies (name, version, suspected flag)
- `versionLookupByPackage` - Async version loading state per package
- `submitLoading`, `submitError`, `submitSuccess` - PR creation status

**Props**:
```typescript
interface AddDependencyPanelProps {
  apiBaseUrl?: string;
  initialEcosystem: Ecosystem;
  allowedEcosystems?: Ecosystem[];
  resolveRepoCoordinates: () => Promise<RepoCoordinates>;
  className?: string;
  client?: DependencyApiClient;
}
```

**Typosquat Warning Severity**: "high" (≥75% confidence), "medium" (<75%)

---

## 5. Add Dependency Panel Component Structure

### Main Component: `add-dependency-panel.tsx` ✅

**Internal UI Components**:
- `SearchResultSkeletonCard` - Animated skeleton loader
- `SearchLoadingPanel` - Loading indicator with spinner
- (Full component is 900+ lines, uses hooks for state management)

**Key Dependencies**:
- React 19 hooks: `useState`, `useCallback`, `useEffect`, `useMemo`, `useRef`
- Fetch API with AbortController for cancellation
- Browser cache for offline/quick access

**Interactions**:
1. User enters search query
2. Debounced search via API with abort support
3. Results displayed with infinite scroll capability
4. Click to select/deselect packages
5. Version picker on selection
6. Suspicious package warnings shown
7. Submit creates GitHub PR with idempotent key

---

## 6. Current Implementation Status Summary

### ✅ IMPLEMENTED
| Component | Status | Location |
|-----------|--------|----------|
| Type Definitions | Complete | `app/types/dashboard.ts`, `app/lib/api/dependency-pr.ts` |
| Dependency Tree Visualization | Complete | `app/components/dependency-tree.tsx` |
| Add Dependency Panel | Complete | `app/components/add-dependency-panel.tsx` |
| Package Search API Client | Complete | `app/lib/api/dependency-pr.ts` |
| Version Fetching API Client | Complete | `app/lib/api/dependency-pr.ts` |
| PR Creation API Client | Complete | `app/lib/api/dependency-pr.ts` |
| Browser Caching | Complete | `app/lib/browser-cache.ts` |
| Session Management | Partial | `app/lib/auth/client-session.ts` (client-side only) |
| Dashboard Layout | Partial | `app/components/dashboard-client.tsx`, `dashboard-sidebar.tsx` |
| Mock Dashboard Data | Complete | `app/lib/mock-dashboard-data.ts` |

### ❌ MISSING / NOT IMPLEMENTED
| Item | Location | Issue |
|------|----------|-------|
| Package Search Backend | `app/api/packages/search/` | Route stub empty |
| Package Versions Backend | `app/api/packages/versions/` | Route stub empty |
| Scan/Analysis Backend | `app/api/repos/:id/scan/` | Not implemented |
| Dynamic Analysis | N/A | Backend integration pending |
| Dashboard Data Fetching | `app/dashboard/repo/[id]/page.tsx` | Uses mock data |
| Repository Listing | N/A | Uses mock data |
| Authentication | `app/api/auth/` | Stubs exist, needs implementation |

### ⚠️ PARTIAL IMPLEMENTATION
| Item | Status | Notes |
|------|--------|-------|
| Repository Page | ~40% | Skeleton present, data loading logic incomplete |
| Dashboard Client | ~50% | UI structure present, real data integration missing |
| Session Handling | ~30% | Token storage working, backend integration needed |

---

## 7. Data Flow Architecture

```
AddDependencyPanel Component
├── resolveRepoCoordinates() → RepoCoordinates { owner, repoName, headers }
├── searchPackages() API Call
│   ├── URL: /api/repos/packages/search?ecosystem=X&q=X&page=X&limit=X
│   ├── Response: PackageSearchResponse { results[], did_you_mean, total }
│   └── Result Processing: Sort by relevance, detect typosquat, merge pages
├── fetchPackageVersions() API Call
│   ├── URL: /api/repos/packages/versions?ecosystem=X&name=X&limit=X
│   └── Response: PackageVersionsResponse { versions[] }
└── createDependencyPr() API Call
    ├── Request: CreateDependencyPrRequest { ecosystem, dependencies[], ... }
    └── Response: CreateDependencyPrResponse { pr_url, pr_number, ... }

DependencyTree Component
├── Input: DependencyNode[] (hierarchical)
├── Uses Dagre for automatic layout
├── Renders with ReactFlow
└── Optional: Scan results mapping via scanResultsMap

Dashboard Layout
├── DashboardSidebar: Session info, repo selection
├── DependencyTree: Visualization
└── Analysis Results: Static + Dynamic analysis panels
```

---

## 8. Environment Configuration

**Key Environment Variables**:
- `NEXT_PUBLIC_API_URL` - Backend API base URL
- `NEXT_PUBLIC_ENABLE_LOGS` - Enable debug logging
- `NEXT_PUBLIC_STRICT_ERROR_LOGS` - Strict error mode
- `NODE_ENV` - Development/production mode

**Cache Configuration** (hardcoded):
- Dashboard snapshot: 20 minutes
- Dependency tree: 10 minutes
- Scan results: 3 minutes
- Max cache: 1.5 MB

---

## 9. Next Steps / Recommendations

1. **Implement Backend Routes**:
   - `/api/packages/search` - Query npm/pypi registries
   - `/api/packages/versions` - Fetch package versions
   - `/api/repos/:repoId/dependencies` - Get/post dependencies

2. **Complete Dashboard Page**:
   - Replace mock data with actual API calls
   - Implement scan result fetching and polling
   - Add error boundaries and retry logic

3. **Authentication**:
   - Implement GitHub OAuth flow completely
   - Integrate session validation with backend

4. **Analysis Features**:
   - Connect static analysis backend
   - Implement dynamic analysis (VM sandbox) UI

5. **Testing**:
   - Unit tests for API utilities
   - Component tests for Add Dependency Panel
   - E2E tests for full dependency addition flow

---

## File Structure Reference

```
app/
├── lib/
│   ├── api/
│   │   └── dependency-pr.ts ✅ (API clients + types)
│   ├── auth/
│   │   ├── client-session.ts ✅
│   │   └── session.ts (not reviewed)
│   ├── browser-cache.ts ✅
│   ├── logger.ts ✅
│   └── mock-dashboard-data.ts ✅
├── types/
│   └── dashboard.ts ✅
├── components/
│   ├── add-dependency-panel.tsx ✅ (900+ lines)
│   ├── dependency-tree.tsx ✅
│   ├── dashboard-client.tsx ~50%
│   ├── dashboard-sidebar.tsx ~50%
│   └── add-dependency-panel.test.tsx (test file)
├── api/
│   ├── auth/
│   │   ├── github/ (stubs)
│   │   └── logout/ (stub)
│   └── packages/ (empty)
├── dashboard/
│   └── repo/[id]/
│       └── page.tsx ~40%
└── login/
    └── page.tsx
```

---

Generated: May 7, 2026
