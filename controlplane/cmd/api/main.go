package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type server struct {
	ddb           *dynamodb.Client
	policiesTable string
	activeTable   string
	auditTable    string
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

func main() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic(err)
	}

	s := &server{
		ddb:           dynamodb.NewFromConfig(cfg),
		policiesTable: mustEnv("POLICIES_TABLE"),
		activeTable:   mustEnv("ACTIVE_TABLE"),
		auditTable:    os.Getenv("AUDIT_TABLE"),
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
		return s.handleGetActive(ctx, tenantID)
	case req.HTTPMethod == http.MethodPost && strings.HasSuffix(req.Path, "/policy/simulate"):
		return s.handleSimulate(ctx, tenantID, req.Body)
	case req.HTTPMethod == http.MethodPost && strings.HasSuffix(req.Path, "/policy"):
		return s.handlePostPolicy(ctx, tenantID, req.Body)
	default:
		return errorResponse(http.StatusNotFound, "route not found"), nil
	}
}

func (s *server) handleGetActive(ctx context.Context, tenantID string) (events.APIGatewayProxyResponse, error) {
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

	resp := activePolicyResponse{
		TenantID:  tenantID,
		Version:   activeVersion,
		Policy:    json.RawMessage(policyJSON),
		UpdatedAt: updatedAt,
	}

	return jsonResponse(http.StatusOK, resp), nil
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

func jsonResponse(status int, payload any) events.APIGatewayProxyResponse {
	body, err := json.Marshal(payload)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "failed to encode response")
	}
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Headers: map[string]string{
			"Content-Type":                "application/json",
			"Access-Control-Allow-Origin": "*",
		},
		Body: string(body),
	}
}

func errorResponse(status int, message string) events.APIGatewayProxyResponse {
	payload := map[string]any{
		"error": message,
	}
	return jsonResponse(status, payload)
}
