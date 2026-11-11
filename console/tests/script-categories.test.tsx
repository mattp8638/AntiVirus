import { expect, test, vi } from "vitest";
vi.mock("../src/app-context", () => ({ useApp: () => ({ can: () => true, toast: () => {} }) }));
import { buildCategoryTree, categoryLabel } from "../src/pages/rmm/Scripts";

test("scripts group into Operating system › Area › Kind with counts", () => {
  const root = buildCategoryTree([
    { category: "Linux / Networking / Fix" }, { category: "Linux / Networking / Check" },
    { category: "Linux / Security / Check" }, { category: "Windows / Security / Check" }, { category: "Maintenance" },
  ]);
  expect(root.count).toBe(5);
  const linux = root.children.get("Linux")!;
  expect(linux.count).toBe(3);
  expect(linux.children.get("Networking")!.count).toBe(2);
  expect(linux.children.get("Networking")!.children.get("Fix")!.path).toBe("Linux / Networking / Fix");
  expect(root.children.get("Maintenance")!.count).toBe(1);  // old single-word categories still show
  expect(categoryLabel("Linux / Networking / Fix")).toBe("Linux › Networking › Fix");
});
