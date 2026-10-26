import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import type { ReactNode } from "react";
import TestRenderer, { act } from "react-test-renderer";
import { createMemoryRouter, MemoryRouter, Route, RouterProvider, Routes } from "react-router";
import { SWRConfig, useSWRConfig, type ScopedMutator } from "swr";
import type { AxiosResponse } from "axios";
import type {
  RenderWorkflowGraphDirection,
  RenderWorkflowGraphFromUrlRequest,
} from "@qltysh/fabro-api-client";

import { GraphViewport } from "../components/graph-viewport";
import { navigation } from "../layouts/navigation";
import { runsApi } from "../lib/api-client";
import { queryKeys } from "../lib/query-keys";
import { setupReactTestEnv, textContent } from "../lib/test-utils";
import Visualize from "./visualize";

interface MockDiagnostic {
  rule: string;
  severity: "error" | "warning" | "info";
  message: string;
  node_id?: string | null;
}

interface MockResponse {
  svg: string;
  notices: MockDiagnostic[];
  warnings: MockDiagnostic[];
  direction?: "lr" | "tb";
}

type Responder = (url: string, direction: RenderWorkflowGraphDirection | undefined) => Promise<MockResponse>;

function defaultResponse(): MockResponse {
  return { svg: "<svg></svg>", notices: [], warnings: [] };
}

let responder: Responder;

// The REAL `useGraphRenderFromUrl` (imported by "./visualize" above, not
// mocked) and the REAL `useSWR`/`queryKeys.graph.renderUrl` it's built on
// run for every test below. Only the network call at the bottom of that
// hook — `runsApi.renderWorkflowGraphFromUrl`, as wrapped by `apiData` —
// is stubbed, by this spy. This is what lets the tests exercise SWR's
// real `keepPreviousData`/cache behaviour — the actual regression surface
// for the findings below — instead of a hand-rolled stand-in for it.
const renderSpy = spyOn(runsApi, "renderWorkflowGraphFromUrl").mockImplementation(
  async (request: RenderWorkflowGraphFromUrlRequest) => {
    const response = await responder(request.url, request.direction);
    return {
      data: response,
      status: 200,
      statusText: "OK",
      headers: {},
      config: {},
    } as unknown as AxiosResponse<MockResponse>;
  },
);

/** The most recent request the production hook sent to the (stubbed) API client. */
function lastRequest(): RenderWorkflowGraphFromUrlRequest | undefined {
  return renderSpy.mock.calls.at(-1)?.[0];
}

const mountedRenderers: TestRenderer.ReactTestRenderer[] = [];

function withSwr(children: ReactNode, dedupingInterval = 2000) {
  return (
    // Matches production (`entry.tsx`): a resubmit/retry within this
    // window must still hit the network for real, not get silently
    // deduped — see `useInvalidateGraphRenderFromUrl`'s `{ revalidate:
    // true }`, which clears SWR's own per-key dedupe entry for exactly
    // this reason.
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval, shouldRetryOnError: false }}>
      {children}
    </SWRConfig>
  );
}

function renderAt(entry: string, dedupingInterval?: number): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      withSwr(
        <MemoryRouter initialEntries={[entry]}>
          <Routes>
            <Route path="/visualize" element={<Visualize />} />
          </Routes>
        </MemoryRouter>,
        dedupingInterval,
      ),
    );
  });
  mountedRenderers.push(renderer);
  return renderer;
}

/** One macrotask tick: lets a mocked fetch's microtask chain (and the state updates it schedules) settle. */
function tick(): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, 0);
  return promise;
}

/** Drains the microtask queue (and the React updates it schedules) so a mocked fetch settles. */
async function flush(): Promise<void> {
  await act(async () => {
    await tick();
  });
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (reason: unknown) => void } {
  const { promise, resolve, reject } = Promise.withResolvers<T>();
  return { promise, resolve, reject };
}

function clickTitle(renderer: TestRenderer.ReactTestRenderer, title: string): void {
  act(() => {
    renderer.root.findAll((n) => n.props?.title === title)[0].props.onClick();
  });
}

/**
 * Exposes the test tree's own bound `mutate` (scoped to `withSwr`'s
 * isolated per-test cache provider, same as the production hooks use —
 * see `useInvalidateGraphRenderFromUrl`) so a test can force a
 * revalidation the production code itself never dispatched: this
 * environment has no `window`/`document` (see `lib/effects.ts`), so
 * SWR's real focus/reconnect listeners never fire here, and this is the
 * only way left to exercise "a background refresh that fails on its
 * own, not one a direction click caused."
 */
function CaptureMutate({
  onReady,
}: {
  onReady: (mutate: ScopedMutator) => void;
}) {
  const { mutate } = useSWRConfig();
  onReady(mutate);
  return null;
}

/**
 * The same shape `isAxiosError`/`apiErrorFromAxios` (lib/api-client.ts)
 * parse a real failed response into: this is what rejects from
 * `runsApi.renderWorkflowGraphFromUrl` on an HTTP error in production, so
 * the tests below exercise the real error-parsing path, not a shortcut.
 */
function axiosErrorFor(code: string, meta?: Record<string, unknown>) {
  return {
    isAxiosError: true,
    message: "fallback message",
    response: {
      status: 400,
      statusText: "Bad Request",
      data: { errors: [{ status: "400", title: "Bad Request", detail: "fallback detail", code, meta }] },
      headers: {},
    },
  };
}

let teardownReactTestEnv: () => void;

beforeEach(() => {
  teardownReactTestEnv = setupReactTestEnv();
  responder = async () => defaultResponse();
  renderSpy.mockClear();
});

afterEach(() => {
  while (mountedRenderers.length) {
    act(() => mountedRenderers.pop()!.unmount());
  }
  teardownReactTestEnv();
});

describe("navigation", () => {
  test("global nav shows Visualize linking to /visualize", () => {
    expect(navigation).toContainEqual(
      expect.objectContaining({ name: "Visualize", href: "/visualize" }),
    );
  });
});

describe("Visualize", () => {
  test("URL + Load sets ?url=<encoded> via router location search", async () => {
    const router = createMemoryRouter(
      [{ path: "/visualize", element: <Visualize /> }],
      { initialEntries: ["/visualize"] },
    );
    let renderer!: TestRenderer.ReactTestRenderer;
    act(() => {
      renderer = TestRenderer.create(withSwr(<RouterProvider router={router} />));
    });
    mountedRenderers.push(renderer);

    const input = renderer.root.findByProps({ id: "visualize-url" });
    act(() => {
      input.props.onChange({ target: { value: "https://example.com/a b.fabro" } });
    });
    act(() => {
      renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
    });

    expect(router.state.location.search).toBe("?url=https%3A%2F%2Fexample.com%2Fa+b.fabro");
    expect(lastRequest()?.url).toBe("https://example.com/a b.fabro");
    expect(lastRequest()?.direction).toBeUndefined();
    expect(textContent(renderer.root)).not.toContain("Removed the GitHub token");
    await flush();
  });

  test("strips a raw.githubusercontent.com token before writing ?url= and shows a hint", async () => {
    const router = createMemoryRouter(
      [{ path: "/visualize", element: <Visualize /> }],
      { initialEntries: ["/visualize"] },
    );
    let renderer!: TestRenderer.ReactTestRenderer;
    act(() => {
      renderer = TestRenderer.create(withSwr(<RouterProvider router={router} />));
    });
    mountedRenderers.push(renderer);

    const input = renderer.root.findByProps({ id: "visualize-url" });
    act(() => {
      input.props.onChange({
        target: {
          value: "https://raw.githubusercontent.com/acme/widgets/main/a.fabro?token=GHSAT0AAAA&ref=main",
        },
      });
    });
    act(() => {
      renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
    });

    expect(router.state.location.search).not.toContain("token");
    expect(decodeURIComponent(router.state.location.search)).toContain("ref=main");
    expect(textContent(renderer.root)).toContain(
      "Removed the GitHub token from the link; Fabro uses its own GitHub access.",
    );
    await flush();
  });

  test("opening /visualize?url=<encoded> calls the endpoint with the decoded URL on mount", async () => {
    renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fa%20b.fabro");

    expect(lastRequest()?.url).toBe("https://example.com/a b.fabro");
    await flush();
  });

  test("resubmitting the same URL revalidates instead of being a no-op", async () => {
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();
    const callsBefore = renderSpy.mock.calls.length;

    act(() => {
      renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
    });

    expect(renderSpy.mock.calls.length).toBe(callsBefore + 1);
    expect(lastRequest()?.url).toBe("https://example.com/workflow.fabro");
    await flush();
  });

  test("browser back/forward restores the input to match ?url=", async () => {
    const router = createMemoryRouter(
      [{ path: "/visualize", element: <Visualize /> }],
      { initialEntries: ["/visualize?url=https%3A%2F%2Fexample.com%2Ffirst.fabro"] },
    );
    let renderer!: TestRenderer.ReactTestRenderer;
    act(() => {
      renderer = TestRenderer.create(withSwr(<RouterProvider router={router} />));
    });
    mountedRenderers.push(renderer);

    expect(
      renderer.root.findByProps({ id: "visualize-url" }).props.value,
    ).toBe("https://example.com/first.fabro");

    await act(async () => {
      await router.navigate("/visualize?url=https%3A%2F%2Fexample.com%2Fsecond.fabro");
    });
    expect(
      renderer.root.findByProps({ id: "visualize-url" }).props.value,
    ).toBe("https://example.com/second.fabro");

    await act(async () => {
      await router.navigate(-1);
    });
    expect(
      renderer.root.findByProps({ id: "visualize-url" }).props.value,
    ).toBe("https://example.com/first.fabro");

    await act(async () => {
      await router.navigate(1);
    });
    expect(
      renderer.root.findByProps({ id: "visualize-url" }).props.value,
    ).toBe("https://example.com/second.fabro");
  });

  const graphLimitCases: Array<[limit: string, max: number, expectedSubstring: string]> = [
    ["nodes", 500, "more than 500 nodes"],
    ["edges", 2000, "more than 2,000 edges"],
    ["statements", 20000, "more than 20,000 statements"],
    ["attribute_text", 3 * 1024 * 1024, "more than 3 MiB of attribute text"],
    ["nesting_depth", 8, "subgraphs nested more than 8 levels deep"],
  ];

  for (const [limit, max, expectedSubstring] of graphLimitCases) {
    test(`graph_too_large names the exceeded limit in plain words for ${limit}`, async () => {
      responder = async () => {
        throw axiosErrorFor("graph_too_large", { limit, count: max + 1, max });
      };
      const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
      await flush();

      const text = textContent(renderer.root);
      expect(text).toContain(expectedSubstring);
      if (limit === "nodes") {
        expect(text).not.toContain("1,000");
      }
    });
  }

  const errorCases: Array<[code: string, expectedSubstring: string]> = [
    ["invalid_url", "not a valid URL"],
    ["scheme_not_https", "https://"],
    ["host_not_allowed", "can't be reached"],
    ["unreachable", "Couldn't connect"],
    ["timeout", "too long"],
    ["http_status", "error loading"],
    ["too_large", "3 MiB"],
    ["graph_too_large", "too large"],
    ["not_parsable", "parsable"],
    ["render_failed", "couldn't check or draw"],
  ];

  for (const [code, expectedSubstring] of errorCases) {
    test(`shows a distinct message for ${code}`, async () => {
      responder = async () => {
        throw axiosErrorFor(code);
      };
      const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
      await flush();

      expect(textContent(renderer.root)).toContain(expectedSubstring);
    });
  }

  test("every error message is distinct", async () => {
    const messages = new Set<string>();
    for (const [code] of errorCases) {
      responder = async () => {
        throw axiosErrorFor(code);
      };
      const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
      await flush();
      messages.add(textContent(renderer.root));
      act(() => renderer.unmount());
    }
    expect(messages.size).toBe(errorCases.length);
  });

  test("validation_failed lists every error diagnostic and renders no graph", async () => {
    responder = async () => {
      throw axiosErrorFor("validation_failed", {
        diagnostics: [
          { rule: "attractor.missing_start", severity: "error", message: "workflow has no start node" },
          { rule: "unsupported.import_cycle", severity: "error", message: "self-import cycle" },
        ],
      });
    };
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();

    const text = textContent(renderer.root);
    expect(text).toContain("workflow has no start node");
    expect(text).toContain("self-import cycle");
    expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(0);
  });

  test("success with notices renders SVG in the shared viewport and lists notices separately from errors", async () => {
    responder = async () => ({
      svg:      "<svg viewBox='0 0 100 100'></svg>",
      notices:  [{ rule: "attractor.file_not_found", severity: "info", message: "prompts/x.md not found" }],
      warnings: [],
    });
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();

    const viewport = renderer.root.findByType(GraphViewport);
    expect(viewport.props.svg).toBe("<svg viewBox='0 0 100 100'></svg>");

    const text = textContent(renderer.root);
    expect(text).toContain("prompts/x.md not found");
    expect(renderer.root.findAll((n) => n.props?.role === "alert")).toHaveLength(0);
  });

  test("no notices renders no notices list", async () => {
    responder = async () => ({ svg: "<svg></svg>", notices: [], warnings: [] });
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();

    expect(textContent(renderer.root)).not.toContain("Referenced files not loaded");
  });

  test("warnings render separately from notices and errors", async () => {
    responder = async () => ({
      svg:      "<svg></svg>",
      notices:  [{ rule: "attractor.file_not_found", severity: "info", message: "x.md not found" }],
      warnings: [{ rule: "attractor.unbound_input", severity: "warning", message: "input `name` is unbound" }],
    });
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();

    const text = textContent(renderer.root);
    expect(text).toContain("input `name` is unbound");
    expect(text).toContain("x.md not found");
    expect(renderer.root.findAll((n) => n.props?.role === "alert")).toHaveLength(0);
  });

  test("direction change re-requests the graph with the new direction", async () => {
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();

    expect(lastRequest()?.direction).toBeUndefined();
    clickTitle(renderer, "Left to right");
    expect(lastRequest()?.direction).toBe("lr");
    clickTitle(renderer, "Top to bottom");
    expect(lastRequest()?.direction).toBe("tb");
    await flush();
  });

  test("shows the server-reported drawn direction when the user hasn't chosen one (AC: LR source shows LR pressed)", async () => {
    responder = async () => ({ ...defaultResponse(), direction: "lr" });
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();

    const lrButton = renderer.root.findAll((n) => n.props?.title === "Left to right")[0];
    const tbButton = renderer.root.findAll((n) => n.props?.title === "Top to bottom")[0];
    expect(lrButton.props["aria-pressed"]).toBe(true);
    expect(tbButton.props["aria-pressed"]).toBe(false);
  });

  test("a user-chosen direction overrides the server-reported source direction", async () => {
    responder = async (_url, direction) => ({ ...defaultResponse(), direction: direction === "tb" ? "tb" : "lr" });
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();
    expect(renderer.root.findAll((n) => n.props?.title === "Left to right")[0].props["aria-pressed"]).toBe(true);

    clickTitle(renderer, "Top to bottom");
    await flush();

    expect(renderer.root.findAll((n) => n.props?.title === "Top to bottom")[0].props["aria-pressed"]).toBe(true);
    expect(renderer.root.findAll((n) => n.props?.title === "Left to right")[0].props["aria-pressed"]).toBe(false);
  });

  test("falls back to TB when neither the user nor the server names a direction", async () => {
    responder = async () => defaultResponse();
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();

    expect(renderer.root.findAll((n) => n.props?.title === "Top to bottom")[0].props["aria-pressed"]).toBe(true);
  });

  const URL_A = "https://example.com/a.fabro";
  const URL_B = "https://example.com/b.fabro";

  function goTo(renderer: TestRenderer.ReactTestRenderer, url: string): void {
    const input = renderer.root.findByProps({ id: "visualize-url" });
    act(() => {
      input.props.onChange({ target: { value: url } });
    });
    act(() => {
      renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
    });
  }

  describe("stale data across a url change (round-4 correctness/ux finding)", () => {
    test("loading a different url that fails shows only its error, not the previous graph or notices; navigating to no url then shows the EmptyState", async () => {
      responder = async (url) => {
        if (url === URL_A) {
          return {
            svg:      "<svg data-a></svg>",
            notices:  [{ rule: "attractor.file_not_found", severity: "info", message: "a-notice: prompts/x.md not found" }],
            warnings: [],
          };
        }
        throw axiosErrorFor("validation_failed", {
          diagnostics: [{ rule: "attractor.missing_start", severity: "error", message: "b-diagnostic: no start node" }],
        });
      };

      const router = createMemoryRouter(
        [{ path: "/visualize", element: <Visualize /> }],
        { initialEntries: [`/visualize?url=${encodeURIComponent(URL_A)}`] },
      );
      let renderer!: TestRenderer.ReactTestRenderer;
      act(() => {
        renderer = TestRenderer.create(withSwr(<RouterProvider router={router} />));
      });
      mountedRenderers.push(renderer);
      await flush();

      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(1);
      expect(textContent(renderer.root)).toContain("a-notice");

      goTo(renderer, URL_B);
      await flush();

      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(0);
      const afterB = textContent(renderer.root);
      expect(afterB).not.toContain("a-notice");
      expect(afterB).not.toContain("<svg data-a>");
      expect(afterB).toContain("b-diagnostic: no start node");

      await act(async () => {
        await router.navigate("/visualize");
      });
      await flush();

      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(0);
      expect(textContent(renderer.root)).toContain("Visualize a workflow");
    });

    test("loading a different url shows LoadingState until it settles, with no stale graph meanwhile", async () => {
      responder = async () => ({
        svg:      "<svg data-a></svg>",
        notices:  [{ rule: "attractor.file_not_found", severity: "info", message: "a-notice" }],
        warnings: [],
      });
      const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
      await flush();
      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(1);

      const pendingB = deferred<MockResponse>();
      responder = async (url) => (url === URL_B ? pendingB.promise : defaultResponse());

      goTo(renderer, URL_B);
      await flush();

      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(0);
      const whilePending = textContent(renderer.root);
      expect(whilePending).not.toContain("a-notice");
      expect(whilePending).toContain("Loading workflow");

      await act(async () => {
        pendingB.resolve({ svg: "<svg data-b></svg>", notices: [], warnings: [] });
        await tick();
      });

      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(1);
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-b></svg>");
    });
  });

  test("a failed direction re-request reverts the direction but keeps the failure visible until the next direction change", async () => {
    responder = async (_url, direction) => {
      if (direction === "lr") throw axiosErrorFor("render_failed");
      return defaultResponse();
    };
    const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
    await flush();
    expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(1);

    clickTitle(renderer, "Left to right");
    await flush();

    const text = textContent(renderer.root);
    expect(text).toContain("Couldn't redraw left to right");
    expect(text).toContain("couldn't check or draw");
    // Reverted to the last good direction, and the graph it drew stays up.
    expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(1);
    const tbButton = renderer.root.findAll((n) => n.props?.title === "Top to bottom")[0];
    expect(tbButton.props["aria-pressed"]).toBe(true);

    // The next direction change (even a failing one) clears the stale message immediately.
    clickTitle(renderer, "Top to bottom");
    expect(textContent(renderer.root)).not.toContain("Couldn't redraw");
    await flush();
  });

  test("a direction re-request that fails with validation_failed shows its diagnostics, not just a one-line message (round-5 finding)", async () => {
    responder = async (_url, direction) => {
      if (direction === "lr") {
        throw axiosErrorFor("validation_failed", {
          diagnostics: [{ rule: "attractor.missing_start", severity: "error", message: "lr-direction: no start node" }],
        });
      }
      return defaultResponse();
    };
    const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
    await flush();

    clickTitle(renderer, "Left to right");
    await flush();

    const text = textContent(renderer.root);
    expect(text).toContain("Couldn't redraw left to right");
    expect(text).toContain("lr-direction: no start node");
  });

  test("a stale, superseded direction request's late success doesn't clear a newer failure (round-5 correctness finding)", async () => {
    const pendingLr = deferred<MockResponse>();
    const pendingTb = deferred<MockResponse>();
    responder = async (_url, direction) => {
      if (direction === "lr") return pendingLr.promise;
      if (direction === "tb") return pendingTb.promise;
      return defaultResponse();
    };
    const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
    await flush();

    clickTitle(renderer, "Left to right"); // dispatch LR, left pending (never settled directly)
    await flush();
    clickTitle(renderer, "Top to bottom"); // supersedes LR before it settles
    await flush();

    await act(async () => {
      pendingTb.reject(axiosErrorFor("render_failed"));
      await tick();
    });
    expect(textContent(renderer.root)).toContain("Couldn't redraw top to bottom");

    // The abandoned LR request settles after TB already failed and
    // reverted. It must not retroactively clear that failure message or
    // otherwise affect the now-current (reverted) direction.
    await act(async () => {
      pendingLr.resolve({ svg: "<svg data-lr></svg>", notices: [], warnings: [] });
      await tick();
    });
    expect(textContent(renderer.root)).toContain("Couldn't redraw top to bottom");

    const tbButton = renderer.root.findAll((n) => n.props?.title === "Top to bottom")[0];
    const lrButton = renderer.root.findAll((n) => n.props?.title === "Left to right")[0];
    expect(tbButton.props["aria-pressed"]).toBe(true);
    expect(lrButton.props["aria-pressed"]).toBe(false);
  });

  test("a failed same-url resubmit draws no graph and isn't reported as a direction failure (round-5 finding)", async () => {
    responder = async () => defaultResponse();
    const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
    await flush();
    expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(1);

    responder = async () => {
      throw axiosErrorFor("validation_failed", {
        diagnostics: [{ rule: "attractor.missing_start", severity: "error", message: "resubmit: no start node" }],
      });
    };
    act(() => {
      renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
    });
    await flush();

    expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(0);
    const text = textContent(renderer.root);
    expect(text).toContain("resubmit: no start node");
    expect(text).not.toContain("Couldn't redraw");
  });

  test("an explicit Load always fetches, even a url already loaded this session, and shows its newest response (round-5 finding)", async () => {
    let aCalls = 0;
    responder = async (url) => {
      if (url === URL_A) {
        aCalls += 1;
        return { svg: `<svg data-a-call="${aCalls}"></svg>`, notices: [], warnings: [] };
      }
      return { svg: "<svg data-b></svg>", notices: [], warnings: [] };
    };
    const renderer = renderAt("/visualize");

    goTo(renderer, URL_A);
    await flush();
    expect(renderSpy.mock.calls.length).toBe(1);
    expect(renderer.root.findByType(GraphViewport).props.svg).toBe('<svg data-a-call="1"></svg>');

    goTo(renderer, URL_B);
    await flush();
    expect(renderSpy.mock.calls.length).toBe(2);
    expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-b></svg>");

    // Back to A: the previous A response is still cached, but Load must
    // fetch again (a third call) rather than silently reusing it, and the
    // newest A response (not the first) must be the one drawn.
    goTo(renderer, URL_A);
    await flush();
    expect(renderSpy.mock.calls.length).toBe(3);
    expect(lastRequest()?.url).toBe(URL_A);
    expect(renderer.root.findByType(GraphViewport).props.svg).toBe('<svg data-a-call="2"></svg>');
  });

  test("Load stays keyboard-focusable (aria-disabled, not disabled) while validating, and ignores a second submit", async () => {
    const pendingA = deferred<MockResponse>();
    responder = async () => pendingA.promise;
    const renderer = renderAt("/visualize?url=https%3A%2F%2Fexample.com%2Fworkflow.fabro");
    await flush();

    const button = renderer.root.findByType("form").findByType("button");
    expect(button.props["aria-disabled"]).toBe("true");
    expect(button.props.disabled).toBeFalsy();

    const callsBefore = renderSpy.mock.calls.length;
    act(() => {
      renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
    });
    expect(renderSpy.mock.calls.length).toBe(callsBefore);

    await act(async () => {
      pendingA.resolve(defaultResponse());
      await tick();
    });

    expect(
      renderer.root.findByType("form").findByType("button").props["aria-disabled"],
    ).toBeUndefined();
  });

  describe("round-6 review findings", () => {
    test("a direction failure on one url doesn't resurface as a different url's graph after Load + browser back (P1)", async () => {
      responder = async (url, direction) => {
        if (url === URL_B && direction === "lr") throw axiosErrorFor("render_failed");
        if (url === URL_B) return { svg: "<svg data-b></svg>", notices: [], warnings: [] };
        return { svg: "<svg data-a></svg>", notices: [], warnings: [] };
      };
      const router = createMemoryRouter(
        [{ path: "/visualize", element: <Visualize /> }],
        { initialEntries: ["/visualize"] },
      );
      let renderer!: TestRenderer.ReactTestRenderer;
      act(() => {
        renderer = TestRenderer.create(withSwr(<RouterProvider router={router} />));
      });
      mountedRenderers.push(renderer);

      goTo(renderer, URL_B);
      await flush();
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-b></svg>");

      clickTitle(renderer, "Left to right"); // fails for B
      await flush();
      expect(textContent(renderer.root)).toContain("Couldn't redraw left to right");

      goTo(renderer, URL_A);
      await flush();
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-a></svg>");

      clickTitle(renderer, "Left to right"); // succeeds for A
      await flush();
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-a></svg>");

      await act(async () => {
        await router.navigate(-1);
      });
      await flush();

      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-b></svg>");
      expect(textContent(renderer.root)).not.toContain("Couldn't redraw");
    });

    test("a key that shows an error again revalidates to a graph once it later succeeds (P2)", async () => {
      responder = async () => defaultResponse();
      const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
      await flush();
      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(1);

      responder = async () => {
        throw axiosErrorFor("validation_failed", {
          diagnostics: [{ rule: "attractor.missing_start", severity: "error", message: "resubmit-fail: no start node" }],
        });
      };
      act(() => {
        renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
      });
      await flush();
      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(0);
      expect(textContent(renderer.root)).toContain("resubmit-fail: no start node");

      responder = async () => ({ svg: "<svg data-recovered></svg>", notices: [], warnings: [] });
      act(() => {
        renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
      });
      await flush();

      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(1);
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-recovered></svg>");
      expect(textContent(renderer.root)).not.toContain("resubmit-fail");
    });

    test("an in-flight retry after a failed resubmit shows LoadingState, not the old graph", async () => {
      responder = async () => ({ svg: "<svg data-original></svg>", notices: [], warnings: [] });
      const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
      await flush();
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-original></svg>");

      responder = async () => {
        throw axiosErrorFor("render_failed");
      };
      act(() => {
        renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
      });
      await flush();
      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(0);

      const pendingRetry = deferred<MockResponse>();
      responder = async () => pendingRetry.promise;
      act(() => {
        renderer.root.findByType("form").props.onSubmit({ preventDefault() {} });
      });
      await flush();

      expect(renderer.root.findAllByType(GraphViewport)).toHaveLength(0);
      expect(textContent(renderer.root)).toContain("Loading workflow");
      expect(renderer.root.findAll((n) => n.props?.role === "alert")).toHaveLength(0);

      await act(async () => {
        pendingRetry.resolve({ svg: "<svg data-retried></svg>", notices: [], warnings: [] });
        await tick();
      });
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-retried></svg>");
    });

    test("Load A -> B -> A back-to-back (well within SWR's dedupingInterval) still issues 3 requests and draws the newest A", async () => {
      let aCalls = 0;
      responder = async (url) => {
        if (url === URL_A) {
          aCalls += 1;
          return { svg: `<svg data-a-call="${aCalls}"></svg>`, notices: [], warnings: [] };
        }
        return { svg: "<svg data-b></svg>", notices: [], warnings: [] };
      };
      const renderer = renderAt("/visualize");

      goTo(renderer, URL_A);
      await flush();
      goTo(renderer, URL_B);
      await flush();
      goTo(renderer, URL_A);
      await flush();

      expect(renderSpy.mock.calls.length).toBe(3);
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe('<svg data-a-call="2"></svg>');
    });

    test("retrying a direction that just failed doesn't flash the main error banner while the retry is in flight", async () => {
      responder = async (_url, direction) => {
        if (direction === "lr") throw axiosErrorFor("render_failed");
        return defaultResponse();
      };
      const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
      await flush();

      clickTitle(renderer, "Left to right");
      await flush();
      expect(textContent(renderer.root)).toContain("Couldn't redraw left to right");
      expect(renderer.root.findAll((n) => n.props?.role === "alert")).toHaveLength(0);

      const pendingRetry = deferred<MockResponse>();
      responder = async (_url, direction) => (direction === "lr" ? pendingRetry.promise : defaultResponse());
      clickTitle(renderer, "Left to right"); // retry the direction that just failed
      await flush();

      // The retried key's own stale error (from the first attempt) must
      // not flash the main alert banner while this retry is in flight.
      expect(renderer.root.findAll((n) => n.props?.role === "alert")).toHaveLength(0);

      await act(async () => {
        pendingRetry.resolve({ svg: "<svg data-lr-retry></svg>", notices: [], warnings: [] });
        await tick();
      });
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-lr-retry></svg>");
      expect(textContent(renderer.root)).not.toContain("Couldn't redraw");
    });

    test("a direction that previously succeeded stays pressed after a different direction fails (kills a requestedDirection mutant)", async () => {
      responder = async (_url, direction) => {
        if (direction === "tb") throw axiosErrorFor("render_failed");
        return defaultResponse();
      };
      const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
      await flush();

      clickTitle(renderer, "Left to right");
      await flush();
      expect(renderer.root.findAll((n) => n.props?.title === "Left to right")[0].props["aria-pressed"]).toBe(true);

      clickTitle(renderer, "Top to bottom");
      await flush();

      expect(textContent(renderer.root)).toContain("Couldn't redraw top to bottom");
      const lrButton = renderer.root.findAll((n) => n.props?.title === "Left to right")[0];
      const tbButton = renderer.root.findAll((n) => n.props?.title === "Top to bottom")[0];
      expect(lrButton.props["aria-pressed"]).toBe(true);
      expect(tbButton.props["aria-pressed"]).toBe(false);
    });

    test("toggling back to a direction already rendered this session sends no new request (revalidateIfStale: false)", async () => {
      // dedupingInterval: 0 — otherwise SWR's own per-key dedupe window
      // (2000ms elsewhere in this file) would also suppress the second
      // LR request, letting this test pass even without
      // `revalidateIfStale: false` on the hook.
      const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`, 0);
      await flush(); // auto direction

      clickTitle(renderer, "Left to right");
      await flush();
      const callsAfterLr = renderSpy.mock.calls.length;

      clickTitle(renderer, "Top to bottom");
      await flush();
      expect(renderSpy.mock.calls.length).toBeGreaterThan(callsAfterLr);

      const callsBeforeSecondLr = renderSpy.mock.calls.length;
      clickTitle(renderer, "Left to right");
      await flush();

      expect(renderSpy.mock.calls.length).toBe(callsBeforeSecondLr);
      expect(renderer.root.findAll((n) => n.props?.title === "Left to right")[0].props["aria-pressed"]).toBe(true);
    });
  });

  describe("round-7 correctness finding: onDirectionChange early return + target-key error check", () => {
    test("a direction that failed earlier succeeds with exactly one request once the server recovers (S1)", async () => {
      let lrShouldFail = true;
      responder = async (_url, direction) => {
        if (direction === "lr") {
          if (lrShouldFail) throw axiosErrorFor("render_failed");
          return { svg: "<svg data-lr></svg>", notices: [], warnings: [] };
        }
        if (direction === "tb") return { svg: "<svg data-tb></svg>", notices: [], warnings: [] };
        return defaultResponse();
      };
      const renderer = renderAt(`/visualize?url=${encodeURIComponent(URL_A)}`);
      await flush();

      clickTitle(renderer, "Left to right"); // fails
      await flush();
      expect(textContent(renderer.root)).toContain("Couldn't redraw left to right");

      clickTitle(renderer, "Top to bottom"); // succeeds; clears directionError (but not LR's own cached error)
      await flush();
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-tb></svg>");
      expect(textContent(renderer.root)).not.toContain("Couldn't redraw");

      lrShouldFail = false; // the server is healthy now
      const callsBefore = renderSpy.mock.calls.length;
      clickTitle(renderer, "Left to right");
      await flush();

      expect(renderSpy.mock.calls.length).toBe(callsBefore + 1);
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-lr></svg>");
      expect(textContent(renderer.root)).not.toContain("Couldn't redraw");
      expect(renderer.root.findAll((n) => n.props?.title === "Left to right")[0].props["aria-pressed"]).toBe(true);
    });

    test("a direction that failed before Load B and Back succeeds with exactly one request once retried (S3)", async () => {
      let lrShouldFail = true;
      responder = async (url, direction) => {
        if (url === URL_A && direction === "lr") {
          if (lrShouldFail) throw axiosErrorFor("render_failed");
          return { svg: "<svg data-a-lr></svg>", notices: [], warnings: [] };
        }
        if (url === URL_A) return { svg: "<svg data-a></svg>", notices: [], warnings: [] };
        return { svg: "<svg data-b></svg>", notices: [], warnings: [] };
      };
      const router = createMemoryRouter(
        [{ path: "/visualize", element: <Visualize /> }],
        { initialEntries: [`/visualize?url=${encodeURIComponent(URL_A)}`] },
      );
      let renderer!: TestRenderer.ReactTestRenderer;
      act(() => {
        renderer = TestRenderer.create(withSwr(<RouterProvider router={router} />));
      });
      mountedRenderers.push(renderer);
      await flush();

      clickTitle(renderer, "Left to right"); // fails for A
      await flush();
      expect(textContent(renderer.root)).toContain("Couldn't redraw left to right");

      goTo(renderer, URL_B);
      await flush();
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-b></svg>");

      await act(async () => {
        await router.navigate(-1);
      });
      await flush();
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-a></svg>");
      expect(textContent(renderer.root)).not.toContain("Couldn't redraw");

      lrShouldFail = false; // the server is healthy now
      const callsBefore = renderSpy.mock.calls.length;
      clickTitle(renderer, "Left to right");
      await flush();

      expect(renderSpy.mock.calls.length).toBe(callsBefore + 1);
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-a-lr></svg>");
      expect(textContent(renderer.root)).not.toContain("Couldn't redraw");
    });

    test("clicking the direction already drawn sends nothing and arms no pending state for a later failed revalidation", async () => {
      let lrShouldFail = false;
      responder = async (_url, direction) => {
        if (direction === "lr") {
          if (lrShouldFail) throw axiosErrorFor("render_failed");
          return { svg: "<svg data-lr></svg>", notices: [], warnings: [] };
        }
        return defaultResponse();
      };
      let boundMutate: ScopedMutator | undefined;
      let renderer!: TestRenderer.ReactTestRenderer;
      act(() => {
        renderer = TestRenderer.create(
          withSwr(
            <>
              <MemoryRouter initialEntries={[`/visualize?url=${encodeURIComponent(URL_A)}`]}>
                <Routes>
                  <Route path="/visualize" element={<Visualize />} />
                </Routes>
              </MemoryRouter>
              <CaptureMutate
                onReady={(m) => {
                  boundMutate = m;
                }}
              />
            </>,
          ),
        );
      });
      mountedRenderers.push(renderer);
      await flush();

      clickTitle(renderer, "Left to right");
      await flush();
      expect(renderer.root.findByType(GraphViewport).props.svg).toBe("<svg data-lr></svg>");

      const callsAfterLr = renderSpy.mock.calls.length;
      clickTitle(renderer, "Left to right"); // already the drawn direction: a no-op
      expect(renderSpy.mock.calls.length).toBe(callsAfterLr);

      // A revalidation this click never dispatched (e.g. a background
      // refresh) fails on its own. If the no-op click above had still
      // armed `pendingDirectionChangeRef` (the pre-fix bug), this would
      // be misread as a direction failure and shown as one below.
      lrShouldFail = true;
      await act(async () => {
        await boundMutate!(queryKeys.graph.renderUrl(URL_A, "LR"));
        await tick();
      });

      expect(textContent(renderer.root)).not.toContain("Couldn't redraw");
    });
  });
});
