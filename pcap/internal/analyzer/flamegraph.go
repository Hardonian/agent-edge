package analyzer

import (
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// FlameNode represents a hierarchical node in the flamegraph.
type FlameNode struct {
	Name     string       `json:"name"`
	Value    float64      `json:"value"`
	Category string       `json:"category"` // "agent", "model", "tool", "mcp", "service", "root"
	Count    int          `json:"count"`
	Children []*FlameNode `json:"children,omitempty"`
}

// FlameMode represents the dimension to aggregate.
type FlameMode string

const (
	FlameModeCost   FlameMode = "COST"
	FlameModeTokens FlameMode = "TOKENS"
	FlameModeTime   FlameMode = "TIME"
	FlameModeCalls  FlameMode = "CALLS"
)

// BuildFlamegraph aggregates events into a hierarchical tree based on causal trace relations or agent topology.
func BuildFlamegraph(events []apcap.Event, mode FlameMode) *FlameNode {
	root := &FlameNode{
		Name:     "Session",
		Category: "root",
		Children: make([]*FlameNode, 0),
	}

	if len(events) == 0 {
		return root
	}

	// Group by destination or operation
	nodesByName := make(map[string]*FlameNode)

	for _, ev := range events {
		var val float64
		switch mode {
		case FlameModeCost:
			if ev.Cost != nil {
				val = ev.Cost.Amount
			}
		case FlameModeTokens:
			if ev.Tokens != nil {
				val = float64(ev.Tokens.TotalTokens)
			}
		case FlameModeTime:
			val = ev.DurationMs
		case FlameModeCalls:
			val = 1.0
		}

		cat := "service"
		if ev.Protocol == apcap.ProtocolModel {
			cat = "model"
		} else if ev.Protocol == apcap.ProtocolMCP {
			cat = "mcp"
		} else if ev.Protocol == apcap.ProtocolTool {
			cat = "tool"
		} else if ev.Protocol == apcap.ProtocolA2A {
			cat = "agent"
		}

		targetName := ev.Destination.Name
		if targetName == "" {
			targetName = ev.Operation
		}

		node, exists := nodesByName[targetName]
		if !exists {
			node = &FlameNode{
				Name:     targetName,
				Category: cat,
				Children: make([]*FlameNode, 0),
			}
			nodesByName[targetName] = node
			root.Children = append(root.Children, node)
		}

		node.Value += val
		node.Count++
		root.Value += val
		root.Count++

		// Add operation child under target node
		opFound := false
		for _, child := range node.Children {
			if child.Name == ev.Operation {
				child.Value += val
				child.Count++
				opFound = true
				break
			}
		}
		if !opFound {
			node.Children = append(node.Children, &FlameNode{
				Name:     ev.Operation,
				Category: cat,
				Value:    val,
				Count:    1,
			})
		}
	}

	return root
}
