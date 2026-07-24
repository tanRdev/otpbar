export type StartupState =
  | { status: "loading" }
  | { status: "ready" }
  | { status: "degraded"; error: string };

export type StartupAction =
  { type: "finished" } | { type: "failed"; error: string } | { type: "reset" };

export const initialStartupState: StartupState = { status: "loading" };

export function startupReducer(
  state: StartupState,
  action: StartupAction,
): StartupState {
  switch (action.type) {
    case "finished":
      return state.status === "degraded" ? state : { status: "ready" };
    case "failed":
      return { status: "degraded", error: action.error };
    case "reset":
      return initialStartupState;
  }
}
