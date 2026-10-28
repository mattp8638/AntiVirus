import { afterEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ErrorNote, useListData } from "../src/components/ui";

vi.mock("../src/api", async (original) => ({
  ...await original<typeof import("../src/api")>(),
  api: vi.fn().mockResolvedValue({ detail: "unexpected success envelope" }),
}));
vi.mock("../src/app-context", () => ({ useApp: () => ({}) }));
afterEach(cleanup);

test("an object response cannot reach a page's array methods", async () => {
  function Page() {
    const { data, error } = useListData<{ name: string }>("devices");
    return <><ErrorNote error={error} />{data?.map((row) => <p key={row.name}>{row.name}</p>)}</>;
  }
  render(<Page />);
  expect((await screen.findByRole("alert")).textContent).toContain("expected a list but received object");
});
