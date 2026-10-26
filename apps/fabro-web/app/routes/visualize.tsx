import { useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { useSWRConfig, unstable_serialize } from "swr";
import type { WorkflowDiagnostic } from "@qltysh/fabro-api-client";

import { EmptyState, LoadingState } from "../components/state";
import { GraphViewport } from "../components/graph-viewport";
import { INPUT_CLASS, PRIMARY_BUTTON_CLASS } from "../components/ui";
import { ApiError } from "../lib/api-client";
import { DEFAULT_GRAPH_VIEW, type GraphView } from "../lib/graph-viewport";
import { queryKeys } from "../lib/query-keys";
import {
  useClearGraphRenderError,
  useGraphRenderFromUrl,
  useInvalidateGraphRenderFromUrl,
  type GraphRenderFromUrlData,
} from "../lib/queries";

export const handle = { wide: true, fullHeight: true };

type Direction = "LR" | "TB";

const DIRECTION_LABELS: Record<Direction, string> = {
  LR: "left to right",
  TB: "top to bottom",
};

const RAW_GITHUB_HOST = "raw.githubusercontent.com";

// Keyed by the typed error `code` the server returns
// (`POST /api/v1/graph/render-url`); see docs/public/api-reference/fabro-api.yaml.
const ERROR_MESSAGES: Record<string, string> = {
  invalid_url: "That's not a valid URL.",
  scheme_not_https: "Only https:// URLs can be loaded.",
  host_not_allowed:
    "That address can't be reached: it's private, local, or the request was redirected somewhere not allowed.",
  unreachable: "Couldn't connect to that URL.",
  timeout: "Loading that URL took too long.",
  http_status: "The server returned an error loading that file.",
  too_large: "That file is larger than the 3 MiB limit.",
  graph_too_large: "That workflow's graph is too large to visualize.",
  not_parsable: "That file isn't a parsable Fabro workflow.",
  render_failed: "Fabro couldn't check or draw this workflow right now. Try again in a moment.",
  validation_failed: "The workflow failed validation.",
};

// AC16: names the exceeded dimension (`meta.limit`) in plain words, using
// the allowed maximum (`meta.max`); see docs/public/api-reference/fabro-api.yaml.
const GRAPH_LIMIT_PHRASES: Record<string, (max: number) => string> = {
  nodes: (max) => `more than ${max.toLocaleString()} nodes`,
  edges: (max) => `more than ${max.toLocaleString()} edges`,
  statements: (max) => `more than ${max.toLocaleString()} statements`,
  attribute_text: (max) => `more than ${Math.round(max / (1024 * 1024))} MiB of attribute text`,
  nesting_depth: (max) => `subgraphs nested more than ${max} levels deep`,
};

interface ErrorResponseEntry {
  code?: string;
  detail?: string;
  meta?: {
    diagnostics?: WorkflowDiagnostic[];
    status?: number;
    limit?: string;
    count?: number;
    max?: number;
  };
}

interface ErrorInfo {
  message: string;
  diagnostics: WorkflowDiagnostic[];
}

function describeError(error: ApiError): ErrorInfo {
  const body = error.body as { errors?: ErrorResponseEntry[] } | null;
  const entry = body?.errors?.[0];
  const code = entry?.code;
  const diagnostics = entry?.meta?.diagnostics ?? [];
  let message = (code && ERROR_MESSAGES[code]) || entry?.detail || error.message;
  if (code === "http_status" && entry?.meta?.status != null) {
    message = `The server returned HTTP ${entry.meta.status} loading that file.`;
  } else if (code === "graph_too_large" && entry?.meta?.limit != null && entry?.meta?.max != null) {
    const phrase = GRAPH_LIMIT_PHRASES[entry.meta.limit]?.(entry.meta.max);
    message = phrase ? `That workflow is too large to visualize: it has ${phrase}.` : message;
  }
  return { message, diagnostics };
}

function DiagnosticsList({ diagnostics }: { diagnostics: WorkflowDiagnostic[] }) {
  if (diagnostics.length === 0) return null;
  return (
    <ul className="mt-2 list-disc space-y-1 pl-5">
      {diagnostics.map((diagnostic, index) => (
        // eslint-disable-next-line react/no-array-index-key
        <li key={index}>
          {diagnostic.message}
          {diagnostic.node_id ? ` (${diagnostic.node_id})` : ""}
          {diagnostic.line != null ? ` [line ${diagnostic.line}]` : ""}
          {diagnostic.fix ? <span className="block text-fg-2/80">Fix: {diagnostic.fix}</span> : null}
        </li>
      ))}
    </ul>
  );
}

/**
 * Drop GitHub's short-lived, user-scoped `token=` query parameter from a
 * `raw.githubusercontent.com` URL before it is written to `?url=` (address
 * bar, browser history, bookmarks, shared links). The server already
 * strips and ignores it (Fabro attaches its own GitHub credentials
 * instead); this keeps it from leaking client-side too. Any other host,
 * or an unparsable URL, is returned unchanged — the server reports
 * `invalid_url` for the latter. `strippedToken` tells the caller whether
 * to explain the silent change to the user.
 */
function stripGithubToken(raw: string): { url: string; strippedToken: boolean } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { url: raw, strippedToken: false };
  }
  if (parsed.hostname !== RAW_GITHUB_HOST || !parsed.searchParams.has("token")) {
    return { url: raw, strippedToken: false };
  }
  parsed.searchParams.delete("token");
  return { url: parsed.toString(), strippedToken: true };
}

/**
 * The route shell: owns the URL search param (the one source of truth for
 * which workflow is loaded).
 */
export default function Visualize() {
  const [searchParams, setSearchParams] = useSearchParams();
  const url = searchParams.get("url") ?? "";

  const onLoad = (nextUrl: string) => {
    setSearchParams(nextUrl ? { url: nextUrl } : {});
  };

  return <VisualizeView url={url} onLoad={onLoad} />;
}

/**
 * Never remounts on a `url` change (that would drop focus from whatever
 * the user was interacting with, e.g. the URL field right after Load): the
 * form stays mounted for the whole page lifetime. `input` and the
 * direction/viewport reset to match an *external* `url` change (browser
 * back/forward, or opening a bookmarked address) using the
 * store-previous-prop-in-state pattern during render — no effect needed
 * (see docs/internal/react-effects-policy.md).
 */
function VisualizeView({ url, onLoad }: { url: string; onLoad: (url: string) => void }) {
  const [input, setInput] = useState(url);
  const [prevUrl, setPrevUrl] = useState(url);
  const [direction, setDirection] = useState<Direction | undefined>(undefined);
  const [lastGoodDirection, setLastGoodDirection] = useState<Direction | undefined>(undefined);
  const [directionError, setDirectionError] = useState<ErrorInfo | null>(null);
  const [view, setView] = useState<GraphView>(DEFAULT_GRAPH_VIEW);
  const [tokenStrippedForUrl, setTokenStrippedForUrl] = useState<string | null>(null);
  // Dedupe sentinels for the derived-during-render blocks below: the exact
  // `data`/`error` object already reacted to, so a render that doesn't
  // carry a new one is a no-op instead of re-running the derivation.
  const [handledData, setHandledData] = useState<GraphRenderFromUrlData | undefined>(undefined);
  const [handledError, setHandledError] = useState<unknown>(undefined);
  // True only while the in-flight request for the current key was started
  // by clicking a direction button (`onDirectionChange`), not by Load or a
  // resubmit. Read (and cleared) once, synchronously, the first render
  // that sees this key's outcome — see the derived block below. Also read
  // (never written) while computing `dataForUrl` just below, to tell a
  // direction change's in-flight request (which should keep the last good
  // graph up — see `useGraphRenderFromUrl`) apart from a plain
  // Load/resubmit's (which shouldn't). Safe to read during render even
  // though it's a ref: every call site that writes it also calls a state
  // setter in the same synchronous block, so a render is always pending
  // by the time anything reads it (see docs/internal/react-effects-policy.md,
  // "use refs deliberately").
  const pendingDirectionChangeRef = useRef(false);

  if (url !== prevUrl) {
    setPrevUrl(url);
    setInput(url);
    setDirection(undefined);
    setLastGoodDirection(undefined);
    setDirectionError(null);
    setHandledData(undefined);
    setHandledError(undefined);
    pendingDirectionChangeRef.current = false;
  }

  // `direction` starts unset and is omitted from the request until the
  // user picks one, so the server draws the file in its own `rankdir`
  // instead of always being forced to TB.
  const { data, error, isLoading, isValidating } = useGraphRenderFromUrl(
    url || undefined,
    direction === "LR" ? "lr" : direction === "TB" ? "tb" : undefined,
  );

  // `data` belongs to this render only when all three hold: it was
  // rendered from this exact `url` (`keepPreviousData` otherwise returns
  // the previous url's — or previous direction's — response); the active
  // key has no `error` (a failed retry's `error` clears only once the
  // retry settles, or once `onDirectionChange` below drops it up front,
  // so a stale `data` substituted in behind a lingering one must not
  // render as current); and, for a plain Load/resubmit specifically (not
  // a direction change — see `pendingDirectionChangeRef`), the active key
  // isn't still loading. `isLoading`, unlike `data`, isn't masked by
  // `keepPreviousData`: it stays true for as long as the active key has
  // no real data of its own yet, which is exactly the window during
  // which a Load/resubmit's cache-clearing (see
  // `useInvalidateGraphRenderFromUrl`) would otherwise leave `data`
  // showing an older, possibly unrelated response until the new one
  // lands. A direction change is excluded from that last check because it
  // intentionally keeps the previous graph (and toolbar) up across its
  // own in-flight request instead.
  const isPlainLoadPending = isLoading && !pendingDirectionChangeRef.current;
  const dataForUrl =
    data && data.sourceUrl === url && !error && !isPlainLoadPending ? data : undefined;

  // Derived from the key actually displayed (`dataForUrl`) and the active
  // key's own `error`, not from an `onSuccess`/`onError` callback: SWR
  // calls those with whichever config is current *when the promise
  // settles*, which can belong to a later render than the one that
  // dispatched the request (e.g. a direction click superseded by another
  // one before the first settles) and would misattribute the result.
  // Reading `data`/`error` here instead only ever reflects the currently
  // active key, so a since-abandoned request's late result can't corrupt
  // this component's state — see GraphRenderFromUrlData.requestedDirection.
  if (dataForUrl && dataForUrl !== handledData) {
    setHandledData(dataForUrl);
    setHandledError(undefined);
    pendingDirectionChangeRef.current = false;
    setLastGoodDirection(
      dataForUrl.requestedDirection === "lr" ? "LR" : dataForUrl.requestedDirection === "tb" ? "TB" : undefined,
    );
    setDirectionError(null);
  } else if (error && error !== handledError) {
    setHandledError(error);
    if (pendingDirectionChangeRef.current) {
      pendingDirectionChangeRef.current = false;
      // A direction re-request that fails leaves `data` as the last good
      // graph (via keepPreviousData); revert the toolbar's direction to
      // match it instead of showing a direction no graph is drawn in. The
      // revert switches the key back to one with no error, so this is the
      // only place that can still show the failure — keep the full
      // ErrorInfo (not just a message) so a validation failure's
      // diagnostics are visible here too, not only on a plain Load.
      setDirection(lastGoodDirection);
      const info =
        error instanceof ApiError
          ? describeError(error)
          : { message: "Something went wrong loading that workflow.", diagnostics: [] };
      setDirectionError({
        message: `Couldn't redraw ${direction ? DIRECTION_LABELS[direction] : "that direction"}: ${info.message}`,
        diagnostics: info.diagnostics,
      });
    }
    // A plain Load/resubmit failure needs no extra handling here:
    // `dataForUrl` above already hides any stale graph for it (via
    // `!error`/`isPlainLoadPending`), and the main error banner
    // (`errorInfo`, below) already reads this same `error` directly (a
    // direction failure, by contrast, keeps the graph up and shows its
    // own message via `directionError` instead — see above).
  }

  const invalidateGraphUrl = useInvalidateGraphRenderFromUrl();
  const clearGraphRenderError = useClearGraphRenderError();
  const { cache } = useSWRConfig();

  const onDirectionChange = (next: Direction) => {
    // Clicking the direction already drawn is a no-op: nothing to
    // fetch, and — critically — nothing to arm
    // `pendingDirectionChangeRef` for, so a later revalidation of this
    // same key that fails on its own (not dispatched by this click,
    // e.g. a background refresh) is never misread as a direction
    // failure by the derived block above.
    if (next === direction) return;
    pendingDirectionChangeRef.current = true;
    // Drop the *target* key's own cached error, not `directionError`:
    // `directionError` names whichever direction most recently reverted
    // *from*, so it goes stale the instant a different direction
    // succeeds (clearing it along the way — see the dataForUrl-handling
    // block above) and stops naming `next` at all once the user has
    // moved on without retrying it — see the "succeeds with exactly one
    // request once the server recovers" tests below, where
    // `directionError` is already null by the time the failed direction
    // is reselected. Reading the target key's own cache entry instead
    // always answers the right question — did *this* key last fail? —
    // no matter what happened to any other key since. SWR never clears
    // `error` just because a new request started (only
    // `isValidating`/`isLoading` — see `useGraphRenderFromUrl`), so
    // without this a direction that failed earlier this session would
    // still read as failed — and so would `errorInfo` below and
    // `dataForUrl` above, both read straight from it — for the length
    // of the retry, not just if it fails again.
    if (cache.get(unstable_serialize(queryKeys.graph.renderUrl(url, next)))?.error) {
      clearGraphRenderError(url, next);
    }
    setDirectionError(null);
    setDirection(next);
  };

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    // Keyboard focus survives Load because the button stays non-`disabled`
    // while validating (aria-disabled only); guard re-entrancy here instead.
    if (isValidating) return;
    const { url: trimmed, strippedToken } = stripGithubToken(input.trim());
    // Keyed by the url it applies to (rather than reset alongside the rest
    // of the state below) so it survives the `url !== prevUrl` render this
    // same submit causes once `onLoad` lands, and clears itself on any
    // later navigation without extra bookkeeping.
    setTokenStrippedForUrl(strippedToken ? trimmed : null);
    pendingDirectionChangeRef.current = false;
    setDirectionError(null);
    if (trimmed) {
      // An explicit Load always fetches — even a url whose response is
      // still cached from earlier this session (`A -> B -> A`), and even
      // a resubmit of the url already showing — by dropping its cached
      // entries and SWR's own dedupe entry for them first
      // (`{ revalidate: true }`, inside `useInvalidateGraphRenderFromUrl`)
      // and having that same call revalidate the url's currently-mounted
      // key directly. `revalidateIfStale: false` on the hook otherwise
      // reuses the cache silently, and SWR's `dedupingInterval` would
      // otherwise fold a resubmit within it into whatever request is
      // still being deduped for that key. Clearing the cache's `data`
      // (not just its `error`) is what makes this request count as
      // `isLoading`, not only `isValidating` — see `isPlainLoadPending`
      // above — so the previous graph is hidden for the whole fetch,
      // not just once it settles; a failure then keeps it hidden
      // afterwards too, via `dataForUrl`'s `!error` term, instead of
      // leaving the previous good response up behind the error. Browser
      // back/forward does not go through this path, so it may still
      // show a cached response for a url visited earlier.
      invalidateGraphUrl(trimmed);
    }
    if (trimmed && trimmed === url) {
      // Resubmitting the same URL doesn't change `url` (so the query key
      // `url` depends on doesn't change either, and `onLoad` below would
      // just push a redundant history entry for it): `invalidateGraphUrl`
      // above already revalidates this exact key along with the rest of
      // the url's cached directions.
      return;
    }
    onLoad(trimmed);
  };

  const errorInfo: ErrorInfo | null =
    error instanceof ApiError
      ? describeError(error)
      : error
        ? { message: "Something went wrong loading that workflow.", diagnostics: [] }
        : null;

  // The server reports the effective rankdir it drew (the request's own
  // `direction` when one was sent; otherwise the source's own `lr`/`tb`
  // rankdir, `tb` when it has none, or omitted for `bt`/`rl`, which the
  // toolbar can't represent). Prefer the user's explicit choice; fall back
  // to that, then to `TB` only when neither is available.
  const drawnDirection: Direction =
    direction ??
    (dataForUrl?.direction === "lr" ? "LR" : dataForUrl?.direction === "tb" ? "TB" : undefined) ??
    "TB";

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 pb-[var(--fabro-interview-dock-clearance,0px)]">
      <form onSubmit={onSubmit} className="flex shrink-0 items-end gap-2">
        <div className="w-full max-w-2xl">
          <label htmlFor="visualize-url" className="mb-1 block text-sm font-medium text-fg-2">
            Workflow URL
          </label>
          <input
            id="visualize-url"
            type="url"
            placeholder="https://raw.githubusercontent.com/owner/repo/branch/path/to/workflow.fabro"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className={INPUT_CLASS}
          />
          {tokenStrippedForUrl === url && (
            <p className="mt-1 text-xs text-fg-muted">
              Removed the GitHub token from the link; Fabro uses its own GitHub access.
            </p>
          )}
        </div>
        <button
          type="submit"
          aria-disabled={isValidating ? "true" : undefined}
          disabled={!input.trim()}
          className={`shrink-0 ${PRIMARY_BUTTON_CLASS}`}
        >
          {isValidating ? "Loading…" : "Load"}
        </button>
      </form>

      {errorInfo && (
        <div
          role="alert"
          className="shrink-0 rounded-md bg-coral/10 p-3 text-sm text-fg-2 outline-1 -outline-offset-1 outline-coral/40"
        >
          <p>{errorInfo.message}</p>
          <DiagnosticsList diagnostics={errorInfo.diagnostics} />
        </div>
      )}

      {directionError && (
        <div role="status" className="shrink-0 text-sm text-fg-muted">
          <p>{directionError.message}</p>
          <DiagnosticsList diagnostics={directionError.diagnostics} />
        </div>
      )}

      {dataForUrl ? (
        <>
          <GraphViewport
            svg={dataForUrl.svg}
            direction={drawnDirection}
            setDirection={onDirectionChange}
            view={view}
            setView={setView}
          />
          {dataForUrl.warnings.length > 0 && (
            <div className="shrink-0 rounded-md bg-amber/10 p-3 text-sm text-fg-2 outline-1 -outline-offset-1 outline-amber/40">
              <p className="font-medium">Warnings</p>
              <ul className="mt-1 max-h-40 list-disc space-y-1 overflow-y-auto pl-5">
                {dataForUrl.warnings.map((warning, index) => (
                  // eslint-disable-next-line react/no-array-index-key
                  <li key={index}>{warning.message}</li>
                ))}
              </ul>
            </div>
          )}
          {dataForUrl.notices.length > 0 && (
            <div className="shrink-0 rounded-md border border-line bg-panel-alt p-3 text-sm text-fg-muted">
              <p className="font-medium text-fg-2">
                Referenced files not loaded (Visualize fetches only this file)
              </p>
              <ul className="mt-1 max-h-40 list-disc space-y-1 overflow-y-auto pl-5">
                {dataForUrl.notices.map((notice, index) => (
                  // eslint-disable-next-line react/no-array-index-key
                  <li key={index}>{notice.message}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : isLoading || isValidating ? (
        !errorInfo && <LoadingState label="Loading workflow…" />
      ) : (
        !url &&
        !errorInfo && (
          <EmptyState
            title="Visualize a workflow"
            description="Paste an https URL to one raw .fabro workflow file to see its graph. Files it references aren't fetched."
          />
        )
      )}
    </div>
  );
}
