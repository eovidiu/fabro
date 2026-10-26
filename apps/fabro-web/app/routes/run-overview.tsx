import { useCallback, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { stagePath } from "../lib/stage-routes";
import { ApiError } from "../lib/api-client";
import { useRun, useRunGraph, useRunGraphSource, useRunStages } from "../lib/queries";
import { FloatingTooltip } from "../components/floating-tooltip";
import { GraphViewport } from "../components/graph-viewport";
import { PlatformRecordsPanel } from "../components/platform-records-panel";
import { RunSummaryPanel } from "../components/run-summary-panel";
import { StagePopover } from "../components/stage-popover";
import { StageSidebar } from "../components/stage-sidebar";
import { useRememberedGraphView } from "../hooks/use-remembered-graph-view";
import { EmptyState, ErrorState } from "../components/state";
import {
  mapRunStagesToSidebarStages,
} from "../lib/stage-sidebar";
import { type RunGraphNodeHover } from "../hooks/use-annotated-run-graph-svg";

export const handle = { wide: true, fullHeight: true };

type Direction = "LR" | "TB";

// Best-effort direction guess for the initial render, before a user picks
// one explicitly: the *first* `rankdir=<word>` match in the raw DOT text —
// including inside a quoted string value (a prompt, a label, a comment)
// that was never an attribute assignment at all — ignoring any later
// root-scope assignment that would actually win. This is **not** what the
// server draws with. `GET /runs/{id}/graph` always draws by
// `fabro_dot::last_root_rankdir`'s semantics (the *last* root-scope
// `rankdir`, quoted or not, matched case-sensitively, parsed from the DOT
// rather than matched against raw text) — the same helper
// `fabro_graphviz::render::detect_rankdir` uses for `render-url`'s
// response `direction` field. A source whose first raw match disagrees
// with that last-assignment value (or whose match is really inside a
// string, or whose case Graphviz does not recognize) can show the wrong
// direction button pressed over the graph this page actually draws.
// Known limitation, not fixed here — see `fabro_dot::last_root_rankdir`'s
// own doc comment for the server's exact rule.
const RANKDIR_RE = /rankdir\s*=\s*(\w+)/;

function parseSourceDirection(source: string | undefined): Direction | undefined {
  const value = source?.match(RANKDIR_RE)?.[1];
  return value === "LR" || value === "TB" ? value : undefined;
}

export default function RunOverview() {
  const { id } = useParams();
  const [direction, setDirection] = useState<Direction | undefined>(undefined);
  const sourceQuery = useRunGraphSource(id, direction === undefined);
  const activeDirection = direction ?? parseSourceDirection(sourceQuery.data ?? undefined) ?? "TB";
  const stagesQuery = useRunStages(id);
  const graphQuery = useRunGraph(id, direction);
  const runQuery = useRun(id);
  const stages = useMemo(
    () => mapRunStagesToSidebarStages(stagesQuery.data),
    [stagesQuery.data],
  );
  const graphSvg = graphQuery.data;
  const graphErrorDescription =
    graphQuery.error instanceof ApiError
      ? graphQuery.error.message
      : graphQuery.error
        ? "The graph render request failed."
        : undefined;
  const apiStatus = runQuery.data?.lifecycle.status;
  const terminalOutcome: "succeeded" | "failed" | "dead" | null =
    apiStatus?.kind === "succeeded" ||
    apiStatus?.kind === "failed" ||
    apiStatus?.kind === "dead"
      ? apiStatus.kind
      : null;
  const navigate = useNavigate();
  const [viewTB, setViewTB] = useRememberedGraphView(id ? `${id}-TB` : undefined);
  const [viewLR, setViewLR] = useRememberedGraphView(id ? `${id}-LR` : undefined);
  const view = activeDirection === "LR" ? viewLR : viewTB;
  const setView = activeDirection === "LR" ? setViewLR : setViewTB;
  const [hoveredNode, setHoveredNode] = useState<RunGraphNodeHover | null>(null);

  // Stable identity: passed to GraphViewport -> useAnnotatedRunGraphSvg,
  // whose DOM-annotation effect depends on it and otherwise rebuilds the
  // SVG's innerHTML (losing hover/animation state) on every render.
  const openStage = useCallback(
    (stageId: string) => {
      if (id) navigate(stagePath(id, stageId));
    },
    [id, navigate],
  );

  return (
    <div className="flex min-h-0 flex-1 gap-6">
      <div className="min-h-0 shrink-0 overflow-y-auto overflow-x-hidden pb-[var(--fabro-interview-dock-clearance,0px)]">
        <StageSidebar stages={stages} runId={id!} />
      </div>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-4 pb-[var(--fabro-interview-dock-clearance,0px)]">
        <div className="shrink-0 space-y-4">
          <RunSummaryPanel runId={id!} />
          <PlatformRecordsPanel runId={id!} />
        </div>
        {graphSvg === undefined && graphQuery.isLoading ? (
          <div className="flex-1" />
        ) : graphSvg ? (
          <GraphViewport
            svg={graphSvg}
            direction={activeDirection}
            setDirection={setDirection}
            view={view}
            setView={setView}
            stages={stages}
            terminalOutcome={terminalOutcome}
            onStageClick={openStage}
            onHoverChange={setHoveredNode}
          />
        ) : graphQuery.error ? (
          <ErrorState
            title="Couldn't render workflow graph"
            description={graphErrorDescription}
            onRetry={() => void graphQuery.mutate()}
          />
        ) : (
          <EmptyState
            title="No workflow graph"
            description="This run doesn't have a renderable graph yet."
          />
        )}
      </div>
      {hoveredNode && (
        <FloatingTooltip
          rect={hoveredNode.rect}
          placement="top"
          className="max-w-[18rem] rounded-lg bg-panel p-3 text-xs text-fg-2 shadow-xl outline-1 -outline-offset-1 outline-line-strong"
        >
          <StagePopover
            runId={id!}
            stage={hoveredNode.stage}
            duration={hoveredNode.stage.duration}
          />
        </FloatingTooltip>
      )}
    </div>
  );
}
