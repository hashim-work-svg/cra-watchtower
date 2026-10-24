// Package clock calculates and tracks compliance reporting deadlines under Article 14
// of the EU Cyber Resilience Act (Regulation EU 2024/2847).
package clock

import (
	"fmt"
	"time"
)

// ClockStatus indicates whether a regulatory reporting window is on time, due soon, or overdue.
type ClockStatus string

const (
	// StatusOnTime indicates sufficient time remains before the statutory deadline.
	StatusOnTime ClockStatus = "ON TIME"
	// StatusDueSoon indicates the deadline is imminent.
	StatusDueSoon ClockStatus = "DUE SOON"
	// StatusOverdue indicates the statutory deadline has elapsed.
	StatusOverdue ClockStatus = "OVERDUE"
	// StatusPending indicates the trigger event (e.g. mitigation release) has not yet occurred.
	StatusPending ClockStatus = "PENDING MITIGATION"
)

// StageDeadline encapsulates a regulatory stage deadline and countdown.
type StageDeadline struct {
	Stage       string        `json:"stage"`
	Description string        `json:"description"`
	Deadline    time.Time     `json:"deadline"`
	Remaining   time.Duration `json:"remaining"`
	Status      ClockStatus   `json:"status"`
}

// Timeline models all statutory reporting deadlines for an actively exploited vulnerability.
type Timeline struct {
	AwarenessTime  time.Time      `json:"awareness_time"`
	MitigationTime *time.Time     `json:"mitigation_time,omitempty"`
	Now            time.Time      `json:"now"`
	EarlyWarning   StageDeadline  `json:"early_warning"`   // 24 hours from awareness
	Notification   StageDeadline  `json:"notification"`    // 72 hours from awareness
	FinalReport    *StageDeadline `json:"final_report,omitempty"` // 14 days from mitigation availability
}

// CalculateTimeline computes CRA Article 14 milestones based on awareness and optional mitigation timestamps.
// All calculations are normalized to UTC to prevent timezone and daylight saving anomalies.
func CalculateTimeline(awareness time.Time, mitigation *time.Time, now time.Time) Timeline {
	awareUTC := awareness.UTC()
	nowUTC := now.UTC()

	// Stage 1: Early Warning (within 24 hours of awareness)
	ewDeadline := awareUTC.Add(24 * time.Hour)
	ewRem := ewDeadline.Sub(nowUTC)
	ewStatus := computeStatus(ewRem, 6*time.Hour)

	// Stage 2: Notification (within 72 hours of awareness)
	notifDeadline := awareUTC.Add(72 * time.Hour)
	notifRem := notifDeadline.Sub(nowUTC)
	notifStatus := computeStatus(notifRem, 12*time.Hour)

	var finalStage *StageDeadline
	if mitigation != nil && !mitigation.IsZero() {
		mitUTC := mitigation.UTC()
		// Stage 3: Final report no later than 14 days after a corrective or mitigating measure becomes available
		finalDeadline := mitUTC.Add(14 * 24 * time.Hour)
		finalRem := finalDeadline.Sub(nowUTC)
		finalStatus := computeStatus(finalRem, 48*time.Hour)

		finalStage = &StageDeadline{
			Stage:       "Stage 3: Final Report",
			Description: "Final report with vulnerability description, remediation, and root cause (due <=14 days after mitigation is available)",
			Deadline:    finalDeadline,
			Remaining:   finalRem,
			Status:      finalStatus,
		}
	}

	return Timeline{
		AwarenessTime:  awareUTC,
		MitigationTime: mitigation,
		Now:            nowUTC,
		EarlyWarning: StageDeadline{
			Stage:       "Stage 1: Early Warning",
			Description: "Early warning notification to CSIRT / ENISA (due <=24h after awareness)",
			Deadline:    ewDeadline,
			Remaining:   ewRem,
			Status:      ewStatus,
		},
		Notification: StageDeadline{
			Stage:       "Stage 2: Vulnerability Notification",
			Description: "Detailed vulnerability notification with sensitivity assessment (due <=72h after awareness)",
			Deadline:    notifDeadline,
			Remaining:   notifRem,
			Status:      notifStatus,
		},
		FinalReport: finalStage,
	}
}

// computeStatus determines if the remaining duration is ON TIME, DUE SOON, or OVERDUE.
func computeStatus(rem time.Duration, dueSoonThreshold time.Duration) ClockStatus {
	if rem < 0 {
		return StatusOverdue
	}
	if rem <= dueSoonThreshold {
		return StatusDueSoon
	}
	return StatusOnTime
}

// FormatDuration formats a time.Duration into a human-readable "Xh Ym" or "Xd Yh" format.
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
		hours := int(d.Hours())
		mins := int(d.Minutes()) % 60
		return fmt.Sprintf("-%dh %dm overdue", hours, mins)
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh remaining", days, hours)
	}
	return fmt.Sprintf("%dh %dm remaining", hours, mins)
}
