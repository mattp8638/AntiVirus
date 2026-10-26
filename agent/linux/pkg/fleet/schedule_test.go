package fleet

import (
	"testing"
	"time"
)

func TestScanPlanParsingAndSlots(t *testing.T) {
	modules := map[string]map[string]interface{}{"antimalware": {
		"quickScanPlan": map[string]interface{}{"off": false, "days": []interface{}{0.0, 1.0, 2.0, 3.0, 4.0}, "minuteOfDay": 540.0},
		"fullScanPlan":  map[string]interface{}{"off": true, "days": []interface{}{}, "minuteOfDay": 0.0},
		"badPlan":       map[string]interface{}{"days": []interface{}{9.0}, "minuteOfDay": 10.0},
	}}
	quick := scanPlan(modules, "quickScanPlan")
	if quick == nil || len(quick.Days) != 5 || quick.MinuteOfDay != 540 {
		t.Fatalf("quick plan = %+v", quick)
	}
	if full := scanPlan(modules, "fullScanPlan"); full == nil || !full.Off {
		t.Fatalf("full plan = %+v", full)
	}
	if scanPlan(modules, "badPlan") != nil || scanPlan(modules, "missing") != nil {
		t.Fatal("unusable plans must be nil")
	}

	loc := time.UTC
	wedMorning := time.Date(2030, 1, 2, 8, 0, 0, 0, loc) // Wednesday 08:00
	slot, ok := latestSlot(quick, wedMorning)
	if !ok || !slot.Equal(time.Date(2030, 1, 1, 9, 0, 0, 0, loc)) {
		t.Fatalf("slot before 09:00 should be yesterday 09:00, got %v", slot)
	}
	sunday := time.Date(2030, 1, 6, 12, 0, 0, 0, loc) // weekend: last slot was Friday
	if slot, _ := latestSlot(quick, sunday); !slot.Equal(time.Date(2030, 1, 4, 9, 0, 0, 0, loc)) {
		t.Fatalf("weekend slot = %v", slot)
	}
	// Due once per slot; a missed slot is caught up.
	if !scanDue(quick, time.Time{}, wedMorning) {
		t.Fatal("never-run scan should be due")
	}
	if scanDue(quick, time.Date(2030, 1, 1, 9, 30, 0, 0, loc), wedMorning) {
		t.Fatal("already ran for this slot")
	}
	if !scanDue(quick, time.Date(2029, 12, 30, 9, 30, 0, 0, loc), wedMorning) {
		t.Fatal("missed slot should be caught up")
	}
	if scanDue(scanPlan(modules, "fullScanPlan"), time.Time{}, wedMorning) {
		t.Fatal("an 'off' schedule never runs")
	}
}

func TestScanScheduleRemembersLastRun(t *testing.T) {
	dir := t.TempDir()
	s := loadScanSchedule(dir)
	at := time.Date(2030, 1, 1, 9, 0, 0, 0, time.UTC)
	s.record("quick", at)
	if got := loadScanSchedule(dir).last("quick"); !got.Equal(at) {
		t.Fatalf("persisted last run = %v", got)
	}
}
