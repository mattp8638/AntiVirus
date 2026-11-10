import { expect, test } from "vitest";
import { descendants, describeRules, groupTree, RULE_FIELDS, type Group } from "../src/components/Groups";

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

test("group rules read as a sentence, and groups without rules say nothing", () => {
  expect(describeRules({ enabled: true, match: "all", conditions: [{ field: "platform", op: "is", value: "windows" }, { field: "hostname", op: "matches", value: "LDN-*" }] }))
    .toBe("Platform is windows and Device name matches LDN-*");
  expect(describeRules({ enabled: true, match: "any", conditions: [{ field: "tag", op: "has", value: "kiosk" }, { field: "ip", op: "in", value: "10.2.0.0/16" }] }))
    .toBe("Tag has kiosk or IP address in 10.2.0.0/16");
  expect(describeRules({ enabled: false, conditions: [{ field: "tag", op: "has", value: "x" }] })).toBe("");
  expect(describeRules(undefined)).toBe("");
});

test("every rule field offers the tests the server accepts", () => {
  expect(Object.fromEntries(Object.entries(RULE_FIELDS).map(([k, f]) => [k, f.ops]))).toEqual({
    platform: ["is", "is not"], role: ["is", "is not"], hostname: ["matches", "does not match"],
    os: ["contains", "does not contain"], tag: ["has", "does not have"], ip: ["in", "not in"] });
});
