package cdmengine

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "math"
)

// Engine is the high-speed local analysis backend used by CD Manager.
// It is intentionally pure Go so gomobile can package it for all Android ABIs.
type Engine struct{}

func NewEngine() *Engine { return &Engine{} }

type Metrics struct {
    SHA256 string  `json:"sha256"`
    Bytes  int     `json:"bytes"`
    Entropy float64 `json:"entropy"`
    Printable float64 `json:"printable"`
    Binary bool `json:"binary"`
}

// Analyze performs fast bounded in-memory analysis. Large files are handled by
// the Kotlin streaming analyzer; this backend is for samples and format engines.
func (e *Engine) Analyze(data []byte) string {
    sum := sha256.Sum256(data)
    counts := [256]int{}
    printable := 0
    for _, b := range data {
        counts[int(b)]++
        if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' { printable++ }
    }
    entropy := 0.0
    if len(data) > 0 {
        n := float64(len(data))
        for _, c := range counts {
            if c == 0 { continue }
            p := float64(c) / n
            entropy -= p * math.Log2(p)
        }
    }
    m := Metrics{
        SHA256: hex.EncodeToString(sum[:]),
        Bytes: len(data),
        Entropy: entropy,
        Printable: func() float64 { if len(data)==0{return 0}; return float64(printable)/float64(len(data))*100 }(),
        Binary: len(data) > 0 && float64(printable)/float64(len(data)) < 0.18,
    }
    b, _ := json.Marshal(m)
    return string(b)
}
