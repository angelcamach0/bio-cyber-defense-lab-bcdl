// SPDX-License-Identifier: AGPL-3.0-only
package analysis

import (
	"encoding/json"
	"io"
	"math"
	"os"
)

const MaxJSONBytes = 64 << 10

// DefaultRules preserves the existing worker defaults, including unused HighScore.
func DefaultRules() Rules {
	return Rules{HighScore: .9, LowScore: .1, ThreatMinReads: 50,
		ThreatMinFraction: .02, FastpMinQ30: .75, CriticalWarningScoreBoost: .2,
		HighThreshold: .8, MediumThreshold: .5}
}

func ApplyRuleDefaults(r Rules) Rules {
	d := DefaultRules()
	if r.HighScore == 0 {
		r.HighScore = d.HighScore
	}
	if r.LowScore == 0 {
		r.LowScore = d.LowScore
	}
	if r.ThreatMinReads == 0 {
		r.ThreatMinReads = d.ThreatMinReads
	}
	if r.ThreatMinFraction == 0 {
		r.ThreatMinFraction = d.ThreatMinFraction
	}
	if r.FastpMinQ30 == 0 {
		r.FastpMinQ30 = d.FastpMinQ30
	}
	if r.CriticalWarningScoreBoost == 0 {
		r.CriticalWarningScoreBoost = d.CriticalWarningScoreBoost
	}
	if r.HighThreshold == 0 {
		r.HighThreshold = d.HighThreshold
	}
	if r.MediumThreshold == 0 {
		r.MediumThreshold = d.MediumThreshold
	}
	return r
}

// LoadRules preserves fallback on read/parse errors while returning a stable
// warning instead of logging a host path. Unknown rule fields remain tolerated,
// as in the worker. Oversized or nonfinite configuration also falls back visibly.
func LoadRules(path string) (Rules, string) {
	b, err := readRulesBytes(path)
	if err != nil {
		return DefaultRules(), err.Error()
	}
	var r Rules
	if json.Unmarshal(b, &r) != nil || !finiteRules(r) {
		return DefaultRules(), "rules_parse_error"
	}
	return ApplyRuleDefaults(r), ""
}

func readRulesBytes(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Code("rules_read_error")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return nil, Code("rules_read_error")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxJSONBytes+1))
	if err != nil {
		return nil, Code("rules_read_error")
	}
	if len(b) > MaxJSONBytes {
		return nil, Code("rules_output_limit")
	}
	return b, nil
}

func finiteRules(r Rules) bool {
	for _, v := range []float64{r.HighScore, r.LowScore, r.ThreatMinFraction, r.FastpMinQ30, r.CriticalWarningScoreBoost, r.HighThreshold, r.MediumThreshold} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	return true
}
