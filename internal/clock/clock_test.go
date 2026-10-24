package clock

import (
	"testing"
	"time"
)

func TestCalculateTimeline(t *testing.T) {
	aware := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)

	t.Run("Immediate evaluation (On Time)", func(t *testing.T) {
		now := aware.Add(2 * time.Hour) // 2h after awareness
		timeline := CalculateTimeline(aware, nil, now)

		if timeline.EarlyWarning.Status != StatusOnTime {
			t.Errorf("expected EarlyWarning ON TIME, got %s", timeline.EarlyWarning.Status)
		}
		if timeline.Notification.Status != StatusOnTime {
			t.Errorf("expected Notification ON TIME, got %s", timeline.Notification.Status)
		}
		if timeline.FinalReport != nil {
			t.Errorf("expected FinalReport to be nil when mitigation is nil")
		}
		if timeline.EarlyWarning.Remaining != 22*time.Hour {
			t.Errorf("expected 22h remaining, got %v", timeline.EarlyWarning.Remaining)
		}
	})

	t.Run("Due Soon evaluation", func(t *testing.T) {
		now := aware.Add(20 * time.Hour) // 4 hours before 24h deadline
		timeline := CalculateTimeline(aware, nil, now)

		if timeline.EarlyWarning.Status != StatusDueSoon {
			t.Errorf("expected EarlyWarning DUE SOON, got %s", timeline.EarlyWarning.Status)
		}
		if timeline.Notification.Status != StatusOnTime {
			t.Errorf("expected Notification ON TIME, got %s", timeline.Notification.Status)
		}
	})

	t.Run("Overdue evaluation", func(t *testing.T) {
		now := aware.Add(26 * time.Hour) // 2 hours past 24h deadline
		timeline := CalculateTimeline(aware, nil, now)

		if timeline.EarlyWarning.Status != StatusOverdue {
			t.Errorf("expected EarlyWarning OVERDUE, got %s", timeline.EarlyWarning.Status)
		}
		if timeline.Notification.Status != StatusOnTime {
			t.Errorf("expected Notification ON TIME, got %s", timeline.Notification.Status)
		}
	})

	t.Run("14-Day Mitigation Clock", func(t *testing.T) {
		mitigation := aware.Add(5 * 24 * time.Hour) // Mitigation available 5 days later
		now := mitigation.Add(2 * 24 * time.Hour)   // 2 days after mitigation available
		timeline := CalculateTimeline(aware, &mitigation, now)

		if timeline.FinalReport == nil {
			t.Fatalf("expected FinalReport to be populated")
		}

		expectedDeadline := mitigation.Add(14 * 24 * time.Hour)
		if !timeline.FinalReport.Deadline.Equal(expectedDeadline) {
			t.Errorf("expected final deadline %v, got %v", expectedDeadline, timeline.FinalReport.Deadline)
		}
		if timeline.FinalReport.Status != StatusOnTime {
			t.Errorf("expected FinalReport ON TIME, got %s", timeline.FinalReport.Status)
		}
		if timeline.FinalReport.Remaining != 12*24*time.Hour {
			t.Errorf("expected 12 days remaining, got %v", timeline.FinalReport.Remaining)
		}
	})

	t.Run("Timezone and DST invariance", func(t *testing.T) {
		locNY, err := time.LoadLocation("America/New_York")
		if err != nil {
			locNY = time.FixedZone("EDT", -4*3600)
		}
		awareNY := time.Date(2026, 10, 24, 6, 0, 0, 0, locNY) // same as 10:00 UTC

		locTokyo := time.FixedZone("JST", 9*3600)
		nowTokyo := time.Date(2026, 10, 24, 21, 0, 0, 0, locTokyo) // 12:00 UTC (2h after awareness)

		timeline := CalculateTimeline(awareNY, nil, nowTokyo)
		if timeline.EarlyWarning.Remaining != 22*time.Hour {
			t.Errorf("expected timezone-safe 22h remaining, got %v", timeline.EarlyWarning.Remaining)
		}
	})
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d        time.Duration
		expected string
	}{
		{5 * time.Hour + 30 * time.Minute, "5h 30m remaining"},
		{2*24*time.Hour + 4*time.Hour, "2d 4h remaining"},
		{-(3 * time.Hour + 15 * time.Minute), "-3h 15m overdue"},
	}

	for _, tc := range tests {
		got := FormatDuration(tc.d)
		if got != tc.expected {
			t.Errorf("FormatDuration(%v) = %q, expected %q", tc.d, got, tc.expected)
		}
	}
}
