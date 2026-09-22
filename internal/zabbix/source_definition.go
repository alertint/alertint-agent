// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SourceVersionAlgorithm identifies ADR-0053's current-definition digest.
const SourceVersionAlgorithm = "zabbix-trigger-effective-v1"

type definitionUnavailableError struct{ reason string }

func (e definitionUnavailableError) Error() string {
	return "zabbix: source definition unavailable: " + e.reason
}

func unavailable(reason string) error { return definitionUnavailableError{reason: reason} }

// DefinitionUnavailableReason returns the closed reason carried by a
// semantic completeness error. Transport errors intentionally return false
// so the caller can classify timeout/auth/availability separately.
func DefinitionUnavailableReason(err error) (string, bool) {
	var target definitionUnavailableError
	if errors.As(err, &target) {
		return target.reason, true
	}
	return "", false
}

type ruleSnapshot struct {
	RootTriggerID string
	Triggers      []ruleTrigger
	Items         []ruleItem
}

type ruleTrigger struct {
	TriggerID, Description, EventName, Status, Priority, Type      string
	Expression, RecoveryMode, RecoveryExpression                   string
	CorrelationMode, CorrelationTag, ManualClose, TemplateID, UUID string
	Hosts                                                          []zHostRef
	Functions                                                      []ruleFunction
	Dependencies                                                   []string
	Tags                                                           []KV
}

type ruleFunction struct {
	ItemID    string `json:"itemid"`
	Function  string `json:"function"`
	Parameter string `json:"parameter"`
}

type ruleItem struct {
	ItemID, HostID, TemplateID, Key, Type, ValueType, Status string
	Delay, Params, MasterItemID, ValueMapID                  string
	Preprocessing                                            []rulePreprocessing
}

type rulePreprocessing struct {
	Type               string `json:"type"`
	Params             string `json:"params"`
	ErrorHandler       string `json:"error_handler"`
	ErrorHandlerParams string `json:"error_handler_params"`
}

// RuleVersionEvidence is the bounded, non-secret explanation persisted for
// one successful source-definition observation.
type RuleVersionEvidence struct {
	Algorithm        string            `json:"algorithm"`
	Version          string            `json:"version"`
	ComponentDigests map[string]string `json:"component_digests"`
	TriggerIDs       []string          `json:"trigger_ids"`
	ItemIDs          []string          `json:"item_ids"`
}

// SourceRuleDefinition is one complete, consistent observation of a Zabbix
// rule's supported effective configuration. It describes current API truth,
// never the historical configuration that produced an older event.
type SourceRuleDefinition struct {
	RuleVersionEvidence

	Source     string `json:"source"`
	InstanceID string `json:"instance_id"`
	RuleID     string `json:"rule_id"`
	Host       string `json:"host"`
	EndpointID string `json:"endpoint_id"`
}

type apiRuleTrigger struct {
	TriggerID          string         `json:"triggerid"`
	Description        string         `json:"description"`
	EventName          string         `json:"event_name"`
	Status             string         `json:"status"`
	Priority           string         `json:"priority"`
	Type               string         `json:"type"`
	Expression         string         `json:"expression"`
	RecoveryMode       string         `json:"recovery_mode"`
	RecoveryExpression string         `json:"recovery_expression"`
	CorrelationMode    string         `json:"correlation_mode"`
	CorrelationTag     string         `json:"correlation_tag"`
	ManualClose        string         `json:"manual_close"`
	TemplateID         string         `json:"templateid"`
	UUID               string         `json:"uuid"`
	Hosts              []zHostRef     `json:"hosts"`
	Functions          []ruleFunction `json:"functions"`
	Dependencies       []struct {
		TriggerID string `json:"triggerid"`
	} `json:"dependencies"`
	Tags []KV `json:"tags"`
}

type apiRuleItem struct {
	ItemID        string              `json:"itemid"`
	HostID        string              `json:"hostid"`
	TemplateID    string              `json:"templateid"`
	Key           string              `json:"key_"`
	Type          string              `json:"type"`
	ValueType     string              `json:"value_type"`
	Status        string              `json:"status"`
	Delay         string              `json:"delay"`
	Params        string              `json:"params"`
	MasterItemID  string              `json:"master_itemid"`
	ValueMapID    string              `json:"valuemapid"`
	Preprocessing []rulePreprocessing `json:"preprocessing"`
}

// SourceRuleVersionBounded performs four requests for a rule without direct
// dependencies, or five with them: root discovery, two complete trigger
// snapshots and two complete item snapshots. A version is returned only when
// both complete snapshots match after canonicalization.
func (c *Client) SourceRuleVersionBounded(ctx context.Context, sourceInstanceID, host, triggerID string,
	before func() error, after func(started bool, err error)) (SourceRuleDefinition, error) {
	if c.instanceID == "" || sourceInstanceID == "" {
		return SourceRuleDefinition{}, unavailable("instance_unknown")
	}
	if c.instanceID != sourceInstanceID {
		return SourceRuleDefinition{}, unavailable("instance_mismatch")
	}
	if strings.TrimSpace(host) == "" || strings.TrimSpace(triggerID) == "" {
		return SourceRuleDefinition{}, unavailable("identity_incomplete")
	}
	discovery, err := c.fetchRuleTriggers(ctx, []string{triggerID}, before, after)
	if err != nil {
		return SourceRuleDefinition{}, err
	}
	if len(discovery) != 1 || discovery[0].TriggerID != triggerID {
		return SourceRuleDefinition{}, unavailable("root_trigger_missing")
	}
	if !triggerHasHost(discovery[0], host) {
		return SourceRuleDefinition{}, unavailable("host_mismatch")
	}
	ids := []string{triggerID}
	for _, dep := range discovery[0].Dependencies {
		ids = append(ids, dep.TriggerID)
	}
	ids = sortedUnique(ids)
	if len(ids) > 17 {
		return SourceRuleDefinition{}, unavailable("dependency_limit_exceeded")
	}

	firstTriggers := discovery
	if len(ids) > 1 {
		firstTriggers, err = c.fetchRuleTriggers(ctx, ids, before, after)
		if err != nil {
			return SourceRuleDefinition{}, err
		}
	}
	firstItems, err := c.fetchRuleItems(ctx, itemIDsFor(firstTriggers), before, after)
	if err != nil {
		return SourceRuleDefinition{}, err
	}
	first := ruleSnapshot{RootTriggerID: triggerID, Triggers: convertRuleTriggers(firstTriggers), Items: convertRuleItems(firstItems)}
	firstVersion, err := canonicalRuleVersion(c.instanceID, c.endpointID, first)
	if err != nil {
		return SourceRuleDefinition{}, err
	}

	secondTriggers, err := c.fetchRuleTriggers(ctx, ids, before, after)
	if err != nil {
		return SourceRuleDefinition{}, err
	}
	secondItems, err := c.fetchRuleItems(ctx, itemIDsFor(secondTriggers), before, after)
	if err != nil {
		return SourceRuleDefinition{}, err
	}
	second := ruleSnapshot{RootTriggerID: triggerID, Triggers: convertRuleTriggers(secondTriggers), Items: convertRuleItems(secondItems)}
	secondVersion, err := canonicalRuleVersion(c.instanceID, c.endpointID, second)
	if err != nil {
		return SourceRuleDefinition{}, err
	}
	if firstVersion.Version != secondVersion.Version {
		return SourceRuleDefinition{}, unavailable("inconsistent_read")
	}
	return SourceRuleDefinition{
		Source: "zabbix", InstanceID: c.instanceID, RuleID: triggerID, Host: host,
		EndpointID: c.endpointID, RuleVersionEvidence: secondVersion,
	}, nil
}

func (c *Client) fetchRuleTriggers(ctx context.Context, ids []string, before func() error,
	after func(started bool, err error)) ([]apiRuleTrigger, error) {
	if len(ids) == 0 {
		return nil, unavailable("trigger_rows_incomplete")
	}
	var rows []apiRuleTrigger
	err := c.callInstrumented(ctx, "trigger.get", map[string]any{
		"triggerids":         ids,
		"output":             []string{"triggerid", "description", "event_name", "status", "priority", "type", "expression", "recovery_mode", "recovery_expression", "correlation_mode", "correlation_tag", "manual_close", "templateid", "uuid"},
		"expandExpression":   true,
		"selectHosts":        []string{"hostid", "host"},
		"selectFunctions":    []string{"itemid", "function", "parameter"},
		"selectDependencies": []string{"triggerid"},
		"selectTags":         []string{"tag", "value"},
	}, &rows, before, after)
	if err != nil {
		return nil, err
	}
	if len(rows) != len(ids) {
		return nil, unavailable("trigger_rows_incomplete")
	}
	return rows, nil
}

func (c *Client) fetchRuleItems(ctx context.Context, ids []string, before func() error,
	after func(started bool, err error)) ([]apiRuleItem, error) {
	if len(ids) == 0 {
		return nil, unavailable("item_rows_incomplete")
	}
	if len(ids) > 32 {
		return nil, unavailable("item_limit_exceeded")
	}
	var rows []apiRuleItem
	err := c.callInstrumented(ctx, "item.get", map[string]any{
		"itemids":             ids,
		"output":              []string{"itemid", "hostid", "templateid", "key_", "type", "value_type", "status", "delay", "params", "master_itemid", "valuemapid"},
		"selectPreprocessing": []string{"type", "params", "error_handler", "error_handler_params"},
	}, &rows, before, after)
	if err != nil {
		return nil, err
	}
	if len(rows) != len(ids) {
		return nil, unavailable("item_rows_incomplete")
	}
	return rows, nil
}

func triggerHasHost(trigger apiRuleTrigger, host string) bool {
	for _, candidate := range trigger.Hosts {
		if candidate.Host == host {
			return true
		}
	}
	return false
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, value := range in {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return out
}

func itemIDsFor(triggers []apiRuleTrigger) []string {
	var ids []string
	for _, trigger := range triggers {
		for _, fn := range trigger.Functions {
			ids = append(ids, fn.ItemID)
		}
	}
	return sortedUnique(ids)
}

func convertRuleTriggers(in []apiRuleTrigger) []ruleTrigger {
	out := make([]ruleTrigger, 0, len(in))
	for _, row := range in {
		deps := make([]string, 0, len(row.Dependencies))
		for _, dep := range row.Dependencies {
			deps = append(deps, dep.TriggerID)
		}
		out = append(out, ruleTrigger{
			TriggerID: row.TriggerID, Description: row.Description, EventName: row.EventName,
			Status: row.Status, Priority: row.Priority, Type: row.Type, Expression: row.Expression,
			RecoveryMode: row.RecoveryMode, RecoveryExpression: row.RecoveryExpression,
			CorrelationMode: row.CorrelationMode, CorrelationTag: row.CorrelationTag,
			ManualClose: row.ManualClose, TemplateID: row.TemplateID, UUID: row.UUID,
			Hosts: row.Hosts, Functions: row.Functions, Dependencies: deps, Tags: row.Tags,
		})
	}
	return out
}

func convertRuleItems(in []apiRuleItem) []ruleItem {
	out := make([]ruleItem, 0, len(in))
	for _, row := range in {
		out = append(out, ruleItem(row))
	}
	return out
}

type canonicalTrigger struct {
	TriggerID, Description, EventName, Status, Priority, Type      string
	Expression, RecoveryMode, RecoveryExpression                   string
	CorrelationMode, CorrelationTag, ManualClose, TemplateID, UUID string
	Hosts                                                          []zHostRef
	Functions                                                      []ruleFunction
	Dependencies                                                   []string
	Tags                                                           []KV
}

type canonicalRule struct {
	InstanceID, EndpointID, RootTriggerID string
	Triggers                              []canonicalTrigger
	Items                                 []ruleItem
}

//nolint:gocyclo // completeness validation deliberately stays beside canonicalization so no supported field can bypass the fail-closed checks
func canonicalRuleVersion(instanceID, endpointID string, snapshot ruleSnapshot) (RuleVersionEvidence, error) {
	if strings.TrimSpace(instanceID) == "" || strings.TrimSpace(endpointID) == "" || strings.TrimSpace(snapshot.RootTriggerID) == "" {
		return RuleVersionEvidence{}, unavailable("identity_incomplete")
	}
	triggers := make([]canonicalTrigger, 0, len(snapshot.Triggers))
	rootFound := false
	triggerIDs := make(map[string]bool, len(snapshot.Triggers))
	for _, in := range snapshot.Triggers {
		if in.TriggerID == "" || triggerIDs[in.TriggerID] {
			return RuleVersionEvidence{}, unavailable("trigger_rows_incomplete")
		}
		triggerIDs[in.TriggerID] = true
		if in.TriggerID == snapshot.RootTriggerID {
			rootFound = true
		} else if len(in.Dependencies) > 0 {
			return RuleVersionEvidence{}, unavailable("unsupported_dependency_depth")
		}
		if containsUnresolved(in.Expression) || containsUnresolved(in.RecoveryExpression) {
			return RuleVersionEvidence{}, unavailable("macro_unresolved")
		}
		for _, tag := range in.Tags {
			if containsMacro(tag.Tag) || containsMacro(tag.Value) {
				return RuleVersionEvidence{}, unavailable("macro_unresolved")
			}
		}
		out := canonicalTrigger{
			TriggerID: in.TriggerID, Description: in.Description, EventName: in.EventName,
			Status: in.Status, Priority: in.Priority, Type: in.Type, Expression: in.Expression,
			RecoveryMode: in.RecoveryMode, RecoveryExpression: in.RecoveryExpression,
			CorrelationMode: in.CorrelationMode, CorrelationTag: in.CorrelationTag,
			ManualClose: in.ManualClose, TemplateID: in.TemplateID, UUID: in.UUID,
			Hosts: slices.Clone(in.Hosts), Functions: slices.Clone(in.Functions),
			Dependencies: slices.Clone(in.Dependencies), Tags: slices.Clone(in.Tags),
		}
		slices.SortFunc(out.Hosts, func(a, b zHostRef) int {
			if c := strings.Compare(a.HostID, b.HostID); c != 0 {
				return c
			}
			return strings.Compare(a.Host, b.Host)
		})
		slices.SortFunc(out.Functions, func(a, b ruleFunction) int {
			if c := strings.Compare(a.ItemID, b.ItemID); c != 0 {
				return c
			}
			if c := strings.Compare(a.Function, b.Function); c != 0 {
				return c
			}
			return strings.Compare(a.Parameter, b.Parameter)
		})
		slices.Sort(out.Dependencies)
		slices.SortFunc(out.Tags, func(a, b KV) int {
			if c := strings.Compare(a.Tag, b.Tag); c != 0 {
				return c
			}
			return strings.Compare(a.Value, b.Value)
		})
		triggers = append(triggers, out)
	}
	if !rootFound {
		return RuleVersionEvidence{}, unavailable("root_trigger_missing")
	}
	rootDeps := map[string]bool{}
	for _, trigger := range triggers {
		if trigger.TriggerID == snapshot.RootTriggerID {
			for _, id := range trigger.Dependencies {
				rootDeps[id] = true
			}
		}
	}
	for id := range rootDeps {
		if !triggerIDs[id] {
			return RuleVersionEvidence{}, unavailable("dependency_rows_incomplete")
		}
	}
	if len(triggerIDs) != len(rootDeps)+1 {
		return RuleVersionEvidence{}, unavailable("trigger_rows_ambiguous")
	}
	slices.SortFunc(triggers, func(a, b canonicalTrigger) int { return strings.Compare(a.TriggerID, b.TriggerID) })

	items := slices.Clone(snapshot.Items)
	itemIDs := make(map[string]bool, len(items))
	for i := range items {
		item := &items[i]
		if item.ItemID == "" || itemIDs[item.ItemID] {
			return RuleVersionEvidence{}, unavailable("item_rows_incomplete")
		}
		itemIDs[item.ItemID] = true
		switch item.Type {
		case "0", "2", "5", "7", "15":
		default:
			return RuleVersionEvidence{}, unavailable("unsupported_item_type")
		}
		if item.MasterItemID != "" && item.MasterItemID != "0" {
			return RuleVersionEvidence{}, unavailable("unsupported_item_type")
		}
		if containsMacro(item.Key) || containsMacro(item.Delay) || containsMacro(item.Params) {
			return RuleVersionEvidence{}, unavailable("macro_unresolved")
		}
		for _, step := range item.Preprocessing {
			if containsMacro(step.Params) || containsMacro(step.ErrorHandlerParams) {
				return RuleVersionEvidence{}, unavailable("macro_unresolved")
			}
		}
	}
	for _, trigger := range triggers {
		for _, fn := range trigger.Functions {
			if !itemIDs[fn.ItemID] {
				return RuleVersionEvidence{}, unavailable("item_rows_incomplete")
			}
		}
	}
	slices.SortFunc(items, func(a, b ruleItem) int { return strings.Compare(a.ItemID, b.ItemID) })

	canonical := canonicalRule{InstanceID: instanceID, EndpointID: endpointID, RootTriggerID: snapshot.RootTriggerID, Triggers: triggers, Items: items}
	version, err := digestJSON(canonical)
	if err != nil {
		return RuleVersionEvidence{}, err
	}
	components := map[string]string{}
	components["logic"], _ = digestJSON(struct{ Triggers []canonicalTrigger }{projectTriggers(triggers, "logic")})
	components["recovery"], _ = digestJSON(struct{ Triggers []canonicalTrigger }{projectTriggers(triggers, "recovery")})
	components["severity_status"], _ = digestJSON(struct{ Triggers []canonicalTrigger }{projectTriggers(triggers, "severity")})
	components["scope"], _ = digestJSON(struct{ Triggers []canonicalTrigger }{projectTriggers(triggers, "scope")})
	components["dependencies"], _ = digestJSON(struct{ Triggers []canonicalTrigger }{projectTriggers(triggers, "dependencies")})
	components["items"], _ = digestJSON(items)
	triggerList := make([]string, 0, len(triggers))
	for _, trigger := range triggers {
		triggerList = append(triggerList, trigger.TriggerID)
	}
	itemList := make([]string, 0, len(items))
	for _, item := range items {
		itemList = append(itemList, item.ItemID)
	}
	return RuleVersionEvidence{
		Algorithm: SourceVersionAlgorithm, Version: "sha256:" + version,
		ComponentDigests: prefixDigests(components), TriggerIDs: triggerList, ItemIDs: itemList,
	}, nil
}

func projectTriggers(in []canonicalTrigger, component string) []canonicalTrigger {
	out := make([]canonicalTrigger, len(in))
	for i, trigger := range in {
		out[i].TriggerID = trigger.TriggerID
		switch component {
		case "logic":
			out[i].Expression, out[i].Type, out[i].Functions = trigger.Expression, trigger.Type, trigger.Functions
		case "recovery":
			out[i].RecoveryMode, out[i].RecoveryExpression, out[i].CorrelationMode, out[i].CorrelationTag, out[i].ManualClose = trigger.RecoveryMode, trigger.RecoveryExpression, trigger.CorrelationMode, trigger.CorrelationTag, trigger.ManualClose
		case "severity":
			out[i].Priority, out[i].Status = trigger.Priority, trigger.Status
		case "scope":
			out[i].Description, out[i].EventName, out[i].Hosts, out[i].Tags = trigger.Description, trigger.EventName, trigger.Hosts, trigger.Tags
		case "dependencies":
			out[i].TemplateID, out[i].UUID, out[i].Dependencies = trigger.TemplateID, trigger.UUID, trigger.Dependencies
		}
	}
	return out
}

func containsMacro(value string) bool {
	return strings.Contains(value, "{$") || strings.Contains(value, "{#")
}
func containsUnresolved(value string) bool {
	return containsMacro(value) || strings.Contains(value, "******")
}

func digestJSON(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("zabbix: canonical source definition: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func prefixDigests(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = "sha256:" + value
	}
	return out
}
