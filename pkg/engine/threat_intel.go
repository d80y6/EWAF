package engine

import (
	"sync"
)

type ThreatIntel struct {
	mu           sync.RWMutex
	IPReputation map[string]int // IP -> Score (higher is worse)
}

func NewThreatIntel() *ThreatIntel {
	return &ThreatIntel{
		IPReputation: make(map[string]int),
	}
}

func (ti *ThreatIntel) IsMalicious(ip string) bool {
	ti.mu.RLock()
	defer ti.mu.RUnlock()

	score, ok := ti.IPReputation[ip]
	return ok && score > 50
}

func (ti *ThreatIntel) UpdateReputation(ip string, score int) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	ti.IPReputation[ip] = score
}

func (ti *ThreatIntel) SetReputation(reputation map[string]int) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	ti.IPReputation = reputation
}
