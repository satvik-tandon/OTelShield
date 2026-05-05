package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type server struct {
	ddb              *dynamodb.Client
	policiesTable    string
	activeTable      string
	auditTable       string
	auditEventsTable string
}

type createPolicyRequest struct {
	Version  string          `json:"version"`
	Policy   json.RawMessage `json:"policy"`
	Activate *bool           `json:"activate"`
}

type activePolicyResponse struct {
	TenantID  string          `json:"tenantId"`
	Version   string          `json:"version"`
	Policy    json.RawMessage `json:"policy"`
	UpdatedAt string          `json:"updatedAt"`
}

type auditCountRequest struct {
	RuleID string `json:"ruleId"`
	Count  int64  `json:"count"`
	Day    string `json:"day,omitempty"`
}

type auditCountRecord struct {
	RuleID    string `json:"ruleId"`
	Count     int64  `json:"count"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type auditEventPayload struct {
	RuleID    string `json:"ruleId"`
	Action    string `json:"action"`
	Key       string `json:"key"`
	Signal    string `json:"signal"`
	Count     int64  `json:"count"`
	Timestamp string `json:"timestamp"`
}

type auditEventsEnvelope struct {
	Events []auditEventPayload `json:"events"`
}

type auditEventRecord struct {
	EventID   string `json:"eventId"`
	RuleID    string `json:"ruleId"`
	Action    string `json:"action"`
	Key       string `json:"key"`
	Signal    string `json:"signal"`
	Count     int64  `json:"count"`
	Timestamp string `json:"timestamp"`
}

func main() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic(err)
	}

	s := &server{
		ddb:              dynamodb.NewFromConfig(cfg),
		policiesTable:    mustEnv("POLICIES_TABLE"),
		activeTable:      mustEnv("ACTIVE_TABLE"),
		auditTable:       mustEnv("AUDIT_TABLE"),
		auditEventsTable: mustEnv("AUDIT_EVENTS_TABLE"),
	}

	lambda.Start(s.handler)
}

func mustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic("missing env var: " + key)
	}
	return value
}

func (s *server) handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	tenantID := req.PathParameters["tenantId"]
	if tenantID == "" {
		return errorResponse(http.StatusBadRequest, "missing tenantId"), nil
	}

	switch {
	case req.HTTPMethod == http.MethodGet && strings.HasSuffix(req.Path, "/policy/active"):
		return s.handleGetActive(ctx, tenantID, req.Headers["If-None-Match"])
	case req.HTTPMethod == http.MethodGet && strings.HasSuffix(req.Path, "/audit/events"):
		return s.handleGetAuditEvents(
			ctx,
			tenantID,
			req.QueryStringParameters["day"],
			req.QueryStringParameters["limit"],
			req.QueryStringParameters["cursor"],
			req.QueryStringParameters["ruleId"],
			req.QueryStringParameters["action"],
			req.QueryStringParameters["signal"],
			req.QueryStringParameters["key"],
		)
	case req.HTTPMethod == http.MethodGet && strings.HasSuffix(req.Path, "/audit"):
		return s.handleGetAudit(ctx, tenantID, req.QueryStringParameters["day"])
	case req.HTTPMethod == http.MethodPost && strings.HasSuffix(req.Path, "/audit/events"):
		return s.handlePostAuditEvents(ctx, tenantID, req.Body)
	case req.HTTPMethod == http.MethodPost && strings.HasSuffix(req.Path, "/audit/counts"):
		return s.handlePostAuditCount(ctx, tenantID, req.Body)
	case req.HTTPMethod == http.MethodPost && strings.HasSuffix(req.Path, "/policy/simulate"):
		return s.handleSimulate(ctx, tenantID, req.Body)
	case req.HTTPMethod == http.MethodPost && strings.HasSuffix(req.Path, "/policy"):
		return s.handlePostPolicy(ctx, tenantID, req.Body)
	default:
		return errorResponse(http.StatusNotFound, "route not found"), nil
	}
}

func (s *server) handleGetActive(ctx context.Context, tenantID, ifNoneMatch string) (events.APIGatewayProxyResponse, error) {
	activeItem, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.activeTable,
		Key: map[string]types.AttributeValue{
			"tenantId": &types.AttributeValueMemberS{Value: tenantID},
		},
	})
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "failed to read active policy"), nil
	}
	if len(activeItem.Item) == 0 {
		return errorResponse(http.StatusNotFound, "active policy not found"), nil
	}

	activeVersion, ok := getStringAttr(activeItem.Item, "activeVersion")
	if !ok {
		return errorResponse(http.StatusInternalServerError, "active policy version missing"), nil
	}
	updatedAt, _ := getStringAttr(activeItem.Item, "updatedAt")

	policyItem, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.policiesTable,
		Key: map[string]types.AttributeValue{
			"tenantId": &types.AttributeValueMemberS{Value: tenantID},
			"version":  &types.AttributeValueMemberS{Value: activeVersion},
		},
	})
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "failed to read policy"), nil
	}
	if len(policyItem.Item) == 0 {
		return errorResponse(http.StatusNotFound, "policy not found"), nil
	}

	policyJSON, ok := getStringAttr(policyItem.Item, "policy_json")
	if !ok {
		return errorResponse(http.StatusInternalServerError, "policy payload missing"), nil
	}
	etag := policyETag(activeVersion, policyJSON)
	if matchesETag(ifNoneMatch, etag) {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusNotModified,
			Headers:    mergeHeaders(map[string]string{"ETag": etag}),
		}, nil
	}

	resp := activePolicyResponse{
		TenantID:  tenantID,
		Version:   activeVersion,
		Policy:    json.RawMessage(policyJSON),
		UpdatedAt: updatedAt,
	}

	return jsonResponseWithHeaders(http.StatusOK, resp, map[string]string{"ETag": etag}), nil
}

func (s *server) handlePostPolicy(ctx context.Context, tenantID, body string) (events.APIGatewayProxyResponse, error) {
	if strings.TrimSpace(body) == "" {
		return errorResponse(http.StatusBadRequest, "empty body"), nil
	}

	var req createPolicyRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return errorResponse(http.StatusBadRequest, "invalid JSON"), nil
	}

	policyJSON := req.Policy
	if len(policyJSON) == 0 {
		policyJSON = json.RawMessage(body)
	}

	version := req.Version
	if version == "" {
		version = time.Now().UTC().Format("20060102T150405Z")
	}

	activate := true
	if req.Activate != nil {
		activate = *req.Activate
	}

	createdAt := time.Now().UTC().Format(time.RFC3339)
	_, err := s.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.policiesTable,
		Item: map[string]types.AttributeValue{
			"tenantId":    &types.AttributeValueMemberS{Value: tenantID},
			"version":     &types.AttributeValueMemberS{Value: version},
			"createdAt":   &types.AttributeValueMemberS{Value: createdAt},
			"policy_json": &types.AttributeValueMemberS{Value: string(policyJSON)},
		},
	})
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "failed to write policy"), nil
	}

	if activate {
		_, err = s.ddb.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: &s.activeTable,
			Item: map[string]types.AttributeValue{
				"tenantId":      &types.AttributeValueMemberS{Value: tenantID},
				"activeVersion": &types.AttributeValueMemberS{Value: version},
				"updatedAt":     &types.AttributeValueMemberS{Value: createdAt},
			},
		})
		if err != nil {
			return errorResponse(http.StatusInternalServerError, "failed to activate policy"), nil
		}
	}

	response := map[string]any{
		"tenantId": tenantID,
		"version":  version,
		"active":   activate,
	}
	return jsonResponse(http.StatusOK, response), nil
}

func (s *server) handleSimulate(_ context.Context, tenantID, body string) (events.APIGatewayProxyResponse, error) {
	if strings.TrimSpace(body) == "" {
		return errorResponse(http.StatusBadRequest, "empty body"), nil
	}
	response := map[string]any{
		"tenantId": tenantID,
		"ok":       true,
		"message":  "simulate is a stub in the MVP",
	}
	return jsonResponse(http.StatusOK, response), nil
}

func (s *server) handlePostAuditCount(ctx context.Context, tenantID, body string) (events.APIGatewayProxyResponse, error) {
	if strings.TrimSpace(body) == "" {
		return errorResponse(http.StatusBadRequest, "empty body"), nil
	}

	var req auditCountRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return errorResponse(http.StatusBadRequest, "invalid JSON"), nil
	}
	req.RuleID = strings.TrimSpace(req.RuleID)
	if req.RuleID == "" {
		return errorResponse(http.StatusBadRequest, "ruleId is required"), nil
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	day, err := normalizeDay(req.Day)
	if err != nil {
		return errorResponse(http.StatusBadRequest, err.Error()), nil
	}

	now := time.Now().UTC().Format(time.RFC3339)
	tenantDay := auditPartitionKey(tenantID, day)
	_, err = s.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.auditTable,
		Key: map[string]types.AttributeValue{
			"tenantDay": &types.AttributeValueMemberS{Value: tenantDay},
			"ruleId":    &types.AttributeValueMemberS{Value: req.RuleID},
		},
		UpdateExpression: awsString("ADD #count :delta SET #updatedAt = :updatedAt"),
		ExpressionAttributeNames: map[string]string{
			"#count":     "count",
			"#updatedAt": "updatedAt",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":delta":     &types.AttributeValueMemberN{Value: strconv.FormatInt(req.Count, 10)},
			":updatedAt": &types.AttributeValueMemberS{Value: now},
		},
	})
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "failed to write audit count"), nil
	}

	resp := map[string]any{
		"tenantId": tenantID,
		"day":      day,
		"ruleId":   req.RuleID,
		"count":    req.Count,
	}
	return jsonResponse(http.StatusOK, resp), nil
}

func (s *server) handleGetAudit(ctx context.Context, tenantID, dayParam string) (events.APIGatewayProxyResponse, error) {
	day, err := normalizeDay(dayParam)
	if err != nil {
		return errorResponse(http.StatusBadRequest, err.Error()), nil
	}
	tenantDay := auditPartitionKey(tenantID, day)

	result, err := s.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              &s.auditTable,
		KeyConditionExpression: awsString("tenantDay = :tenantDay"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":tenantDay": &types.AttributeValueMemberS{Value: tenantDay},
		},
	})
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "failed to read audit counts"), nil
	}

	records := make([]auditCountRecord, 0, len(result.Items))
	for _, item := range result.Items {
		ruleID, _ := getStringAttr(item, "ruleId")
		count, _ := getInt64Attr(item, "count")
		updatedAt, _ := getStringAttr(item, "updatedAt")
		if ruleID == "" {
			continue
		}
		records = append(records, auditCountRecord{
			RuleID:    ruleID,
			Count:     count,
			UpdatedAt: updatedAt,
		})
	}

	resp := map[string]any{
		"tenantId": tenantID,
		"day":      day,
		"counts":   records,
	}
	return jsonResponse(http.StatusOK, resp), nil
}

func (s *server) handlePostAuditEvents(ctx context.Context, tenantID, body string) (events.APIGatewayProxyResponse, error) {
	if strings.TrimSpace(body) == "" {
		return errorResponse(http.StatusBadRequest, "empty body"), nil
	}

	var envelope auditEventsEnvelope
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return errorResponse(http.StatusBadRequest, "invalid JSON"), nil
	}

	eventsPayload := envelope.Events
	if len(eventsPayload) == 0 {
		var single auditEventPayload
		if err := json.Unmarshal([]byte(body), &single); err == nil && strings.TrimSpace(single.RuleID) != "" {
			eventsPayload = []auditEventPayload{single}
		}
	}
	if len(eventsPayload) == 0 {
		return errorResponse(http.StatusBadRequest, "no events provided"), nil
	}

	now := time.Now().UTC()
	accepted := 0
	dropped := 0
	for _, event := range eventsPayload {
		ruleID := strings.TrimSpace(event.RuleID)
		if ruleID == "" {
			dropped++
			continue
		}
		if event.Count <= 0 {
			event.Count = 1
		}
		ts, tsString := parseEventTimestamp(event.Timestamp, now)
		tenantDay := auditPartitionKey(tenantID, ts.Format("2006-01-02"))
		eventID := fmt.Sprintf("%s#%s", tsString, randomHex(6))

		item := map[string]types.AttributeValue{
			"tenantDay": &types.AttributeValueMemberS{Value: tenantDay},
			"eventId":   &types.AttributeValueMemberS{Value: eventID},
			"ruleId":    &types.AttributeValueMemberS{Value: ruleID},
			"action":    &types.AttributeValueMemberS{Value: strings.TrimSpace(event.Action)},
			"key":       &types.AttributeValueMemberS{Value: strings.TrimSpace(event.Key)},
			"signal":    &types.AttributeValueMemberS{Value: strings.TrimSpace(event.Signal)},
			"count":     &types.AttributeValueMemberN{Value: strconv.FormatInt(event.Count, 10)},
			"timestamp": &types.AttributeValueMemberS{Value: tsString},
			"createdAt": &types.AttributeValueMemberS{Value: now.Format(time.RFC3339Nano)},
		}
		_, err := s.ddb.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: &s.auditEventsTable,
			Item:      item,
		})
		if err != nil {
			return errorResponse(http.StatusInternalServerError, "failed to write audit events"), nil
		}
		accepted++
	}

	resp := map[string]any{
		"tenantId": tenantID,
		"accepted": accepted,
		"dropped":  dropped,
	}
	return jsonResponse(http.StatusOK, resp), nil
}

func (s *server) handleGetAuditEvents(ctx context.Context, tenantID, dayParam, limitParam, cursorParam, ruleIDParam, actionParam, signalParam, keyParam string) (events.APIGatewayProxyResponse, error) {
	day, err := normalizeDay(dayParam)
	if err != nil {
		return errorResponse(http.StatusBadRequest, err.Error()), nil
	}
	limit := parseLimit(limitParam, 200, 1000)
	tenantDay := auditPartitionKey(tenantID, day)

	ruleID := strings.TrimSpace(ruleIDParam)
	action := strings.TrimSpace(actionParam)
	signal := strings.TrimSpace(signalParam)
	key := strings.TrimSpace(keyParam)

	query := &dynamodb.QueryInput{
		TableName:              &s.auditEventsTable,
		KeyConditionExpression: awsString("tenantDay = :tenantDay"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":tenantDay": &types.AttributeValueMemberS{Value: tenantDay},
		},
		ScanIndexForward: awsBool(false),
	}

	filterNames := map[string]string{}
	filterValues := query.ExpressionAttributeValues
	filterParts := make([]string, 0, 4)
	if ruleID != "" {
		filterNames["#ruleId"] = "ruleId"
		filterValues[":ruleId"] = &types.AttributeValueMemberS{Value: ruleID}
		filterParts = append(filterParts, "contains(#ruleId, :ruleId)")
	}
	if action != "" {
		filterNames["#action"] = "action"
		filterValues[":action"] = &types.AttributeValueMemberS{Value: action}
		filterParts = append(filterParts, "#action = :action")
	}
	if signal != "" {
		filterNames["#signal"] = "signal"
		filterValues[":signal"] = &types.AttributeValueMemberS{Value: signal}
		filterParts = append(filterParts, "#signal = :signal")
	}
	if key != "" {
		filterNames["#key"] = "key"
		filterValues[":key"] = &types.AttributeValueMemberS{Value: key}
		filterParts = append(filterParts, "contains(#key, :key)")
	}
	if len(filterParts) > 0 {
		query.FilterExpression = awsString(strings.Join(filterParts, " AND "))
		query.ExpressionAttributeNames = filterNames
	}
	if limit > 0 {
		query.Limit = awsInt32(int32(limit))
	}
	if strings.TrimSpace(cursorParam) != "" {
		eventID, err := decodeCursor(cursorParam)
		if err != nil {
			return errorResponse(http.StatusBadRequest, "invalid cursor"), nil
		}
		query.ExclusiveStartKey = map[string]types.AttributeValue{
			"tenantDay": &types.AttributeValueMemberS{Value: tenantDay},
			"eventId":   &types.AttributeValueMemberS{Value: eventID},
		}
	}

	result, err := s.ddb.Query(ctx, query)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "failed to read audit events"), nil
	}

	records := make([]auditEventRecord, 0, len(result.Items))
	for _, item := range result.Items {
		eventID, _ := getStringAttr(item, "eventId")
		ruleID, _ := getStringAttr(item, "ruleId")
		action, _ := getStringAttr(item, "action")
		key, _ := getStringAttr(item, "key")
		signal, _ := getStringAttr(item, "signal")
		timestamp, _ := getStringAttr(item, "timestamp")
		count, _ := getInt64Attr(item, "count")
		if ruleID == "" {
			continue
		}
		records = append(records, auditEventRecord{
			EventID:   eventID,
			RuleID:    ruleID,
			Action:    action,
			Key:       key,
			Signal:    signal,
			Count:     count,
			Timestamp: timestamp,
		})
	}

	resp := map[string]any{
		"tenantId": tenantID,
		"day":      day,
		"events":   records,
	}
	if result.LastEvaluatedKey != nil {
		if eventID, ok := getStringAttr(result.LastEvaluatedKey, "eventId"); ok && eventID != "" {
			resp["nextCursor"] = encodeCursor(eventID)
		}
	}
	return jsonResponse(http.StatusOK, resp), nil
}

func getStringAttr(item map[string]types.AttributeValue, key string) (string, bool) {
	value, ok := item[key]
	if !ok {
		return "", false
	}
	s, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		return "", false
	}
	return s.Value, true
}

func getInt64Attr(item map[string]types.AttributeValue, key string) (int64, bool) {
	value, ok := item[key]
	if !ok {
		return 0, false
	}
	n, ok := value.(*types.AttributeValueMemberN)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func jsonResponse(status int, payload any) events.APIGatewayProxyResponse {
	return jsonResponseWithHeaders(status, payload, nil)
}

func jsonResponseWithHeaders(status int, payload any, extra map[string]string) events.APIGatewayProxyResponse {
	body, err := json.Marshal(payload)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    mergeHeaders(nil),
			Body:       `{"error":"failed to encode response"}`,
		}
	}
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Headers:    mergeHeaders(extra),
		Body:       string(body),
	}
}

func errorResponse(status int, message string) events.APIGatewayProxyResponse {
	payload := map[string]any{
		"error": message,
	}
	return jsonResponse(status, payload)
}

func mergeHeaders(extra map[string]string) map[string]string {
	headers := map[string]string{
		"Content-Type":                "application/json",
		"Access-Control-Allow-Origin": "*",
	}
	for key, value := range extra {
		headers[key] = value
	}
	return headers
}

func policyETag(version, policyJSON string) string {
	sum := sha256.Sum256([]byte(version + ":" + policyJSON))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func matchesETag(ifNoneMatch, etag string) bool {
	candidates := strings.Split(ifNoneMatch, ",")
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == etag {
			return true
		}
	}
	return false
}

func normalizeDay(day string) (string, error) {
	day = strings.TrimSpace(day)
	if day == "" {
		return time.Now().UTC().Format("2006-01-02"), nil
	}
	if _, err := time.Parse("2006-01-02", day); err != nil {
		return "", fmt.Errorf("invalid day format, expected YYYY-MM-DD")
	}
	return day, nil
}

func auditPartitionKey(tenantID, day string) string {
	return tenantID + "#" + day
}

func parseLimit(raw string, fallback, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return fallback
	}
	if limit > max {
		return max
	}
	return limit
}

func parseEventTimestamp(raw string, fallback time.Time) (time.Time, string) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			utc := ts.UTC()
			return utc, utc.Format(time.RFC3339Nano)
		}
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			utc := ts.UTC()
			return utc, utc.Format(time.RFC3339Nano)
		}
	}
	utc := fallback.UTC()
	return utc, utc.Format(time.RFC3339Nano)
}

func randomHex(n int) string {
	if n <= 0 {
		return "0"
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(buf)
}

func encodeCursor(eventID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(eventID))
}

func decodeCursor(cursor string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(cursor))
	if err != nil {
		return "", err
	}
	eventID := strings.TrimSpace(string(decoded))
	if eventID == "" {
		return "", fmt.Errorf("empty cursor")
	}
	return eventID, nil
}

func awsString(v string) *string {
	return &v
}

func awsBool(v bool) *bool {
	return &v
}

func awsInt32(v int32) *int32 {
	return &v
}
