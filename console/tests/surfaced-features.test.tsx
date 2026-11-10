import { expect, test } from "vitest";
import { anomalyText, daysLeft } from "../src/components/Analytics";
import { flattenSettings, settingDifferences, showSetting } from "../src/pages/Policies";

test("disk forecasts read as plain time left", () => {
  expect(daysLeft({ status: "exhausted", daysRemaining: 0 })).toBe("full now");
  expect(daysLeft({ status: "stable", daysRemaining: null })).toBe("not filling up");
  expect(daysLeft({ status: "critical", daysRemaining: 0.4 })).toBe("under a day");
  expect(daysLeft({ status: "warning", daysRemaining: 12.3 })).toBe("12 days");
  expect(daysLeft({ status: "ok", daysRemaining: 400 })).toBe("13 months");
});

test("unusual resource use says what and against what normal", () => {
  expect(anomalyText({ metric: "cpu", currentValue: 97.2, baselineMean: 12.4, isSustained: true, consecutiveSpikes: 4 }))
    .toBe("CPU at 97% against a normal of 12%, for 4 checks in a row");
  expect(anomalyText({ metric: "memory", currentValue: 91, baselineMean: 40, isSustained: false })).toBe("Memory at 91% against a normal of 40%");
});

test("policy previews list only the settings that change", () => {
  const before = flattenSettings({ antimalware: { realtime: true, cloudLookup: true }, dns: { blockedCategories: ["malware"] } });
  const after = flattenSettings({ antimalware: { realtime: true, cloudLookup: false }, dns: { blockedCategories: ["malware", "phishing"] }, usb: { block: true } });
  expect(settingDifferences(before, after).map((r) => [r.setting, showSetting(r.before), showSetting(r.after)])).toEqual([
    ["antimalware.cloudLookup", "on", "off"], ["dns.blockedCategories", "malware", "malware, phishing"], ["usb.block", "not set", "on"]]);
});
