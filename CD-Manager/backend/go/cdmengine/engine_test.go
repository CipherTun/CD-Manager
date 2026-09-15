package cdmengine

import (
    "encoding/json"
    "testing"
)

func TestAnalyze(t *testing.T) {
    got := NewEngine().Analyze([]byte("hello world"))
    var m Metrics
    if err := json.Unmarshal([]byte(got), &m); err != nil { t.Fatal(err) }
    if m.Bytes != 11 || m.SHA256 == "" { t.Fatalf("bad metrics: %+v", m) }
}
