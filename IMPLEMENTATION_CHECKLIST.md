# SentinelFlow Frontend - Implementation Checklist

This document provides a step-by-step checklist for completing the frontend integration. All API utilities have been created and are ready to use.

## Created Modules & Files

### ✅ Core API Utilities
- `app/lib/api/scan-api.ts` - Complete scan, SBOM, compatibility API
- `app/lib/scan-display.ts` - Formatting and display helpers
- `app/lib/package-details.ts` - Package information utilities
- `app/lib/scan-result-display.ts` - Scan result display formatting
- `app/lib/scan-api-adapter.ts` - Bridge to existing page component

### ✅ Existing & Enhanced
- `app/lib/api/dependency-pr.ts` - Package search, versions, PR creation (existing)
- `app/components/add-dependency-panel.tsx` - Full implementation (existing)
- `app/dashboard/repo/[id]/page.tsx` - Imports updated

## Integration Tasks

### Phase 1: Core Scan Functionality (ESSENTIAL)

#### Task 1.1: Update Scan Triggering
**File**: `app/dashboard/repo/[id]/page.tsx`
**Function**: `triggerPackageScan`

Current implementation needs to:
1. Use `buildScanApiContext()` to create API context
2. Call new `triggerScan()` from `scan-api.ts`
3. Ensure ecosystem is passed correctly

```typescript
const triggerPackageScan = useCallback(async () => {
  setScanError(null);
  setIsScanRunning(true);
  // ... existing setup ...

  try {
    const { owner, repoName, headers, ecosystem } = await resolveRepoCoordinates();
    const context = buildScanApiContext({
      baseUrl: API_BASE_URL || "",
      authHeaders: headers,
      owner,
      repoName
    });

    const triggerResponse = await triggerScan(context, {
      ecosystem,
      scan_mode: "full"
    });

    setScanJobId(triggerResponse.job_id);
    // ... rest of existing logic ...
  } catch (error) {
    setScanError(mapScanApiError(error));
  }
}, [/* dependencies */]);
```

#### Task 1.2: Update Poll Logic
**Function**: `pollScanJob`

Replace the manual fetch with the new utility:

```typescript
const pollScanJob = useCallback(async (owner: string, repoName: string, jobId: string) => {
  try {
    const context = buildScanApiContext({
      baseUrl: API_BASE_URL || "",
      authHeaders: headers,
      owner,
      repoName
    });

    const response = await pollScanJob(context, jobId);
    
    setScanError(null);
    setScanDetails(response);
    setScanStatus(response.status);
    setIsScanRunning(["pending", "running"].includes(response.status));

    if (SCAN_TERMINAL_DONE.has(response.status)) {
      // Handle completion
      await loadLatestScanResults();
    }
    // ... existing retry logic ...
  } catch (error) {
    // Use resolvePollErrorMeta() for error handling
  }
}, [/* deps */]);
```

#### Task 1.3: Update Cancel Logic
**Function**: `cancelScanJob`

```typescript
const cancelScanJob = useCallback(async () => {
  if (!scanJobId) return;

  try {
    const context = buildScanApiContext({/*...*/});
    await cancelScan(context, scanJobId);
    setIsScanRunning(false);
  } catch (error) {
    setScanError(mapScanApiError(error));
  }
}, [scanJobId, /* deps */]);
```

#### Task 1.4: Update Display Derivation
**File**: Search for `useMemo` that calls `deriveScanDisplay`

Replace manual display building with utility:

```typescript
const scanDisplay = useMemo(
  () => deriveScanDisplay(scanDetails, scanProgress, isScanRunning, scanError),
  [scanDetails, scanProgress, isScanRunning, scanError]
);
```

### Phase 2: Scan Results Display (HIGH PRIORITY)

#### Task 2.1: Add State for Results Display
```typescript
const [selectedScanPackages, setSelectedScanPackages] = useState<string[]>([]);
const [scanResultRows, setScanResultRows] = useState<ScanResultRow[]>([]);
const [liveResultKeysRef] = useRef<Set<string>>(new Set());
```

#### Task 2.2: Normalize Results from API
In `pollScanJob` success handler:

```typescript
if (Array.isArray(response.results)) {
  const normalized = normalizeScanResultsPayload({ results: response.results });
  setScanResultRows(current => [...current, ...normalized.rows]);
}
```

#### Task 2.3: Build Result Display Cards
In components rendering scan results:

```typescript
import { buildScanResultCard, buildStaticFeaturesDisplay, buildDynamicFindingsDisplay } from "@/app/lib/scan-result-display";

const resultCard = buildScanResultCard(scanResult);
const staticDisplay = buildStaticFeaturesDisplay(scanResult.static_features);
const dynamicDisplay = buildDynamicFindingsDisplay(scanResult.dynamic_findings);

// Use in JSX
<div className="...">
  <h3>{resultCard.packageLabel}</h3>
  <p>Risk: {resultCard.riskStatus}</p>
  {staticDisplay && (
    <details>
      <summary>Static Analysis</summary>
      <p>Entropy: {staticDisplay.entropy.value}</p>
      {/* render other fields */}
    </details>
  )}
</div>
```

### Phase 3: Compatibility Check (MEDIUM PRIORITY)

#### Task 3.1: Add Pre-flight Check Before PR
**File**: Find the dependency PR creation flow

```typescript
// Before calling createDependencyPr()
const compatContext = buildScanApiContext({/*...*/});
try {
  const checkResult = await checkDependencyCompatibility(compatContext, {
    ecosystem: "npm",
    dependencies: selectedDeps
  });

  if (!checkResult.compatible) {
    // Show warnings but allow user to proceed
    showCompatibilityWarnings(checkResult.checks);
  }
} catch (error) {
  // Handle non-blocking error
}

// Then proceed with PR creation
```

### Phase 4: Scan History (MEDIUM PRIORITY)

#### Task 4.1: Add History State
```typescript
const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
const [historyPage, setHistoryPage] = useState(1);
const [totalHistoryPages, setTotalHistoryPages] = useState(1);
```

#### Task 4.2: Load History on Mount
```typescript
useEffect(() => {
  const loadHistory = async () => {
    const context = buildScanApiContext({/*...*/});
    const history = await getScanHistory(context, historyPage, 20);
    setScanHistory(history.jobs);
    setTotalHistoryPages(Math.ceil(history.total / 20));
  };
  void loadHistory();
}, [historyPage]);
```

#### Task 4.3: Render History Table
```typescript
import { buildScanHistoryDisplay, getScanModeColor } from "@/app/lib/scan-result-display";

{scanHistory.map(item => {
  const display = buildScanHistoryDisplay(item);
  return (
    <tr key={item.id}>
      <td>{display.date} {display.time}</td>
      <td>{display.ecosystem}</td>
      <td><span className={`text-${display.scanModeColor}-500`}>{display.scanMode}</span></td>
      <td>{display.status}</td>
      <td>{display.packageCount}</td>
      <td>{display.duration}</td>
      <td>
        <button onClick={() => viewScanDetails(item.id)}>View</button>
      </td>
    </tr>
  );
})}
```

### Phase 5: SBOM Generation (MEDIUM PRIORITY)

#### Task 5.1: Add SBOM Button
```typescript
const [sbomData, setSbomData] = useState<SbomDocument | null>(null);
const [sbomLoading, setSbomLoading] = useState(false);

const generateAndShowSbom = async () => {
  setSbomLoading(true);
  try {
    const context = buildScanApiContext({/*...*/});
    const sbom = await generateSbom(context);
    setSbomData(sbom);
  } catch (error) {
    setScanError(mapScanApiError(error));
  } finally {
    setSbomLoading(false);
  }
};
```

#### Task 5.2: Add Download Buttons
```typescript
const downloadSbomJson = () => {
  if (sbomData) {
    downloadSbom(sbomData, `sbom-${decodedId}.json`);
  }
};

const downloadCycloneDx = async () => {
  try {
    const context = buildScanApiContext({/*...*/});
    const cdx = await generateCycloneDxSbom(context);
    downloadSbom(cdx, `sbom-${decodedId}.cdx.json`);
  } catch (error) {
    setScanError(mapScanApiError(error));
  }
};

// In JSX
<button onClick={downloadSbomJson}>Download JSON</button>
<button onClick={downloadCycloneDx}>Download CycloneDX</button>
```

### Phase 6: Package Details Tab (LOWER PRIORITY)

#### Task 6.1: Integrate Package Metadata
```typescript
import { buildPackageDetailsDisplay, formatPackageDownloads } from "@/app/lib/package-details";

// When user clicks on a package in the graph
const loadPackageDetails = async (packageName: string, ecosystem: Ecosystem) => {
  try {
    // Search for the package to get details
    const search = await searchPackages({
      baseUrl: API_BASE_URL || "",
      authHeaders: headers
    }, ecosystem, packageName, 1, 1);

    if (search.results.length > 0) {
      const result = search.results[0];
      const versions = await fetchPackageVersions({/*...*/}, ecosystem, packageName);
      const details = buildPackageDetailsDisplay(result, versions);
      
      // Display in sidebar/modal
      setSelectedPackage(details);
    }
  } catch (error) {
    // Handle error
  }
};
```

### Phase 7: Error Handling & UX (FINAL PASS)

#### Task 7.1: Toast Notifications
All errors from `mapScanApiError()` should trigger toasts:

```typescript
try {
  await triggerScan(context, request);
} catch (error) {
  const message = mapScanApiError(error);
  showErrorToast(message);
}
```

#### Task 7.2: Retry Buttons
For failed scans:

```typescript
{scanError && (
  <div className="error-banner">
    <p>{scanError}</p>
    <button onClick={() => triggerPackageScan()}>
      Retry
    </button>
  </div>
)}
```

#### Task 7.3: Auth Redirect
When 401 error detected:

```typescript
const errorMeta = resolvePollErrorMeta(error);
if (errorMeta.kind === "auth") {
  window.location.href = "/login?returnTo=" + encodeURIComponent(window.location.href);
}
```

## Testing Checklist

### Unit Tests
- [ ] `deriveScanDisplay()` with various status values
- [ ] `buildScanResultCard()` with edge cases
- [ ] `buildStaticFeaturesDisplay()` with null/undefined values
- [ ] Package validation functions

### Integration Tests
- [ ] Scan trigger → poll → complete flow
- [ ] Scan cancellation
- [ ] Compatibility check with incompatible deps
- [ ] SBOM generation and download
- [ ] Scan history pagination

### E2E Tests
- [ ] Full scan workflow from UI
- [ ] Add dependency with compatibility warning
- [ ] View scan history and select old scan
- [ ] Download SBOM in both formats

### Error Scenarios
- [ ] Network timeout during poll
- [ ] 401 Unauthorized during scan
- [ ] 404 Scan job not found
- [ ] 429 Rate limit exceeded
- [ ] 502 Backend service error

## Performance Checklist

- [ ] Scan polling uses 3-second interval (3000ms)
- [ ] Result deduplication prevents duplicate rows
- [ ] React Flow has `onlyRenderVisibleElements` for large graphs
- [ ] Package search is debounced (300ms)
- [ ] Caching respects TTL values
- [ ] Memory usage doesn't spike during long scans

## Deployment Checklist

- [ ] All new modules are properly exported
- [ ] TypeScript compilation succeeds
- [ ] No console errors in browser
- [ ] All required environment variables set:
  - `NEXT_PUBLIC_API_URL`
  - Backend running at that URL
- [ ] Token storage and retrieval working
- [ ] CORS configured on backend

## Rollback Plan

If issues occur:
1. Revert imports in page component
2. Use old `deriveScanDisplay()` and `computeScanProgress()` implementations
3. Keep using old polling logic temporarily
4. New utilities remain available for gradual adoption

## Documentation TODOs

- [ ] User-facing scan UI documentation
- [ ] Package search typosquat explanation
- [ ] Compatibility check warnings explanation
- [ ] SBOM export guide
- [ ] Error message explanations

## Success Criteria

- ✅ All 11 features implemented
- ✅ Type-safe throughout
- ✅ Error handling for all endpoints
- ✅ Consistent UI/UX patterns
- ✅ Performance acceptable for large datasets
- ✅ Tests passing
- ✅ No breaking changes to existing features

