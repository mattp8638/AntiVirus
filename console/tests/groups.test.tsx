import { expect, test } from "vitest";
import { descendants, groupTree, type Group } from "../src/components/Groups";

const g = (id: string, name: string, parentId: string | null = null): Group => ({ id, tenantId: "t", name, parentId, policyId: null });

test("groups are listed as a tree, children under their parent, alphabetically", () => {
  const tree = groupTree([g("3", "Floor 2", "2"), g("1", "Offices"), g("2", "Leeds", "1"), g("4", "Bristol", "1"), g("5", "Servers")]);
  expect(tree.map((t) => [t.path, t.depth])).toEqual([
    ["Offices", 0], ["Offices › Bristol", 1], ["Offices › Leeds", 1], ["Offices › Leeds › Floor 2", 2], ["Servers", 0]]);
});

test("a group whose parent is not visible still shows, at the top", () => {
  expect(groupTree([g("2", "Leeds", "missing")]).map((t) => t.path)).toEqual(["Leeds"]);
});

test("a group cannot be moved under itself or anything below it", () => {
  const all = [g("1", "Offices"), g("2", "Leeds", "1"), g("3", "Floor 2", "2"), g("4", "Servers")];
  expect([...descendants(all, "1")].sort()).toEqual(["1", "2", "3"]);
});
