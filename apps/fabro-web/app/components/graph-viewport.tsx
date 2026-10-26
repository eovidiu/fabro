import { useCallback, useRef } from "react";
import type { Dispatch, SetStateAction } from "react";

import { useElementEvent } from "../hooks/effects";
import {
  useAnnotatedRunGraphSvg,
  type RunGraphNodeHover,
} from "../hooks/use-annotated-run-graph-svg";
import { clampZoom, type GraphView, wheelZoomFactor, zoomAtPoint } from "../lib/graph-viewport";
import type { Stage } from "../lib/stage-sidebar";
import { GraphToolbar } from "./graph-toolbar";

type Direction = "LR" | "TB";

// Non-passive so the wheel handler can call preventDefault on the browser's own ⌘-zoom.
// Kept at module scope for a stable identity, since the effect resubscribes when its
// options object changes.
const WHEEL_LISTENER_OPTS: AddEventListenerOptions = { passive: false };

const NO_STAGES: Stage[] = [];
const noop = () => {};

/**
 * The pan/zoom/fit graph viewport shared by Run Overview (which annotates
 * nodes with live stage status) and Visualize (a plain, unannotated graph
 * loaded from a URL). Owns the SVG mount point, pointer drag, wheel zoom and
 * fit-to-window; direction and viewport state are controlled by the caller
 * so each page decides what a direction change means (Run Overview re-reads
 * the stored graph, Visualize re-requests the render).
 */
export function GraphViewport({
  svg,
  direction,
  setDirection,
  view,
  setView,
  stages = NO_STAGES,
  terminalOutcome = null,
  onStageClick = noop,
  onHoverChange = noop,
}: {
  svg: string | null | undefined;
  direction: Direction;
  setDirection: (d: Direction) => void;
  view: GraphView;
  setView: Dispatch<SetStateAction<GraphView>>;
  stages?: Stage[];
  terminalOutcome?: "succeeded" | "failed" | "dead" | null;
  onStageClick?: (stageId: string) => void;
  onHoverChange?: (hover: RunGraphNodeHover | null) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const innerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dragState = useRef<{ startX: number; startY: number; startPanX: number; startPanY: number } | null>(null);

  useAnnotatedRunGraphSvg({
    graphSvg: svg,
    innerRef,
    onHoverChange,
    onStageClick,
    stages,
    svgRef,
    terminalOutcome,
  });

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    if (e.target instanceof Element && e.target.closest("button, .node")) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    dragState.current = { startX: e.clientX, startY: e.clientY, startPanX: view.pan.x, startPanY: view.pan.y };
  }, [view.pan]);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    const drag = dragState.current;
    if (!drag) return;
    setView((v) => ({
      ...v,
      pan: {
        x: drag.startPanX + e.clientX - drag.startX,
        y: drag.startPanY + e.clientY - drag.startY,
      },
    }));
  }, [setView]);

  const onPointerUp = useCallback(() => {
    dragState.current = null;
  }, []);

  // Two-finger scroll pans; ⌘/Ctrl + scroll (and trackpad pinch, which arrives as
  // ctrl+wheel) zooms anchored at the cursor. Native listener so preventDefault sticks.
  const onWheel = useCallback((e: WheelEvent) => {
    const el = containerRef.current;
    if (!el) return;
    e.preventDefault();
    if (e.ctrlKey || e.metaKey) {
      const r = el.getBoundingClientRect();
      const cursor = { x: e.clientX - (r.left + r.width / 2), y: e.clientY - (r.top + r.height / 2) };
      setView((v) => zoomAtPoint(v, wheelZoomFactor(e.deltaY), cursor, direction));
    } else {
      setView((v) => ({ ...v, pan: { x: v.pan.x - e.deltaX, y: v.pan.y - e.deltaY } }));
    }
  }, [direction, setView]);
  // The container only exists once the graph has loaded, so gate the listener on
  // svg. The effect then re-runs and binds once the container is on the page.
  useElementEvent(containerRef, "wheel", onWheel, WHEEL_LISTENER_OPTS, Boolean(svg));

  const fitToWindow = useCallback(() => {
    const svgEl = svgRef.current;
    const container = containerRef.current;
    if (!svgEl || !container) return;

    const svgW = svgEl.viewBox.baseVal.width || svgEl.getBoundingClientRect().width;
    const svgH = svgEl.viewBox.baseVal.height || svgEl.getBoundingClientRect().height;
    const padPx = 48;
    const containerW = container.clientWidth - padPx;
    const containerH = container.clientHeight - padPx;

    const fitPct = Math.min(containerW / svgW, containerH / svgH) * 100;
    setView({ zoom: clampZoom(fitPct, direction), pan: { x: 0, y: 0 } });
  }, [direction, setView]);

  return (
    <div className="graph-svg relative flex min-h-0 flex-1 flex-col rounded-md border border-line bg-panel-alt">
      <GraphToolbar
        direction={direction}
        setDirection={setDirection}
        fitToWindow={fitToWindow}
        zoom={view.zoom}
        onZoomBy={(factor) => setView((v) => zoomAtPoint(v, factor, undefined, direction))}
      />

      <div
        ref={containerRef}
        className="min-h-0 flex-1 touch-none overflow-hidden overscroll-contain p-6"
        style={{ cursor: dragState.current ? "grabbing" : "grab" }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      >
        <div
          ref={innerRef}
          className="flex h-full items-center justify-center [&_svg]:mx-auto [&_svg]:block"
          style={{ transform: `translate(${view.pan.x}px, ${view.pan.y}px) scale(${view.zoom / 100})`, transformOrigin: "center center" }}
        />
      </div>
    </div>
  );
}
