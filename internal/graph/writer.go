package graph

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Writer provides Cypher-based data access layer for Memgraph.
type Writer struct {
	driver neo4j.DriverWithContext
}

// NewWriter creates a new Writer wrapping the provided neo4j driver.
func NewWriter(driver neo4j.DriverWithContext) *Writer {
	return &Writer{driver: driver}
}

// Close closes the underlying driver connection.
func (w *Writer) Close(ctx context.Context) error {
	return w.driver.Close(ctx)
}

// EvidenceRecord represents evidence metadata for upsert operations.
type EvidenceRecord struct {
	LogIndex        int64
	Digest          string
	ReceiptDigest   string
	ArtifactType    string
	Status          string
	SubjectID       string
	PublisherIssuer string
	PublisherSub    string
	Sealed          time.Time
}

// EntityRecord represents an entity (Capability, Threat, Control, etc.) for upsert.
type EntityRecord struct {
	ID               string
	Label            string
	Properties       map[string]any
	EvidenceLogIndex int64
}

// EdgeRecord represents a relationship between two entities.
type EdgeRecord struct {
	FromID    string
	FromLabel string
	ToID      string
	ToLabel   string
	EdgeType  string
}

// EvidenceFilter provides filtering and pagination for evidence queries.
type EvidenceFilter struct {
	ArtifactType *string
	Since        *time.Time
	Before       *time.Time
	Cursor       *string
	Limit        *int
}

// ThreatModelResult contains the assembled threat model for a subject.
type ThreatModelResult struct {
	SubjectID    string
	Capabilities []ThreatModelCapability
	Threats      []ThreatModelThreat
	Controls     []ThreatModelControl
	Vectors      []ThreatModelVector
}

// SubjectSummaryResult contains summary statistics for a subject.
type SubjectSummaryResult struct {
	SubjectID      string
	EvidenceCount  int64
	PublisherCount int
	ArtifactTypes  map[string]ArtifactTypeSummary
}

// EvidenceResult contains paginated evidence list with next cursor.
type EvidenceResult struct {
	SubjectID  string
	Evidence   []EvidenceItem
	NextCursor *string
}

// CoverageResult contains coverage statistics for a catalog.
type CoverageResult struct {
	SubjectID   string
	Catalog     string
	CatalogType string
	Covered     int
	Total       int
	Controls    []CoverageControl
}

// UpsertSubject creates or updates a Subject node.
func (w *Writer) UpsertSubject(ctx context.Context, subjectID string) error {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	cypher := `MERGE (s:Subject {id: $id})`
	result, err := session.Run(ctx, cypher, map[string]any{"id": subjectID})
	if err != nil {
		return err
	}
	// Consume result to complete the query
	_, err = result.Consume(ctx)
	return err
}

// UpsertPublisher creates or updates a Publisher node.
func (w *Writer) UpsertPublisher(ctx context.Context, issuer, sub string) error {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	cypher := `MERGE (p:Publisher {issuer: $issuer, sub: $sub})`
	result, err := session.Run(ctx, cypher, map[string]any{"issuer": issuer, "sub": sub})
	if err != nil {
		return err
	}
	_, err = result.Consume(ctx)
	return err
}

// UpsertEvidence creates or updates an Evidence node with edges to subject and publisher.
func (w *Writer) UpsertEvidence(ctx context.Context, ev EvidenceRecord) error {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	cypher := `
		MATCH (s:Subject {id: $subjectID})
		MATCH (p:Publisher {issuer: $issuer, sub: $sub})
		MERGE (e:Evidence {logIndex: $logIndex})
		SET e.digest = $digest,
		    e.receiptDigest = $receiptDigest,
		    e.artifactType = $artifactType,
		    e.status = $status,
		    e.sealed = $sealed
		MERGE (e)-[:TARGETS]->(s)
		MERGE (e)-[:PUBLISHED_BY]->(p)
	`
	params := map[string]any{
		"logIndex":      ev.LogIndex,
		"digest":        ev.Digest,
		"receiptDigest": ev.ReceiptDigest,
		"artifactType":  ev.ArtifactType,
		"status":        ev.Status,
		"sealed":        neo4j.LocalDateTimeOf(ev.Sealed),
		"subjectID":     ev.SubjectID,
		"issuer":        ev.PublisherIssuer,
		"sub":           ev.PublisherSub,
	}
	result, err := session.Run(ctx, cypher, params)
	if err != nil {
		return err
	}
	_, err = result.Consume(ctx)
	return err
}

// UpsertEntity creates or updates an entity node with dynamic label and properties.
// Creates DEFINES edge from the evidence that defines this entity.
func (w *Writer) UpsertEntity(ctx context.Context, entity EntityRecord) error {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Build properties SET clause
	cypher := fmt.Sprintf(`
		MERGE (n:%s {id: $id})
		SET n += $properties
		WITH n
		MATCH (e:Evidence {logIndex: $logIndex})
		MERGE (e)-[:DEFINES]->(n)
	`, entity.Label)

	params := map[string]any{
		"id":         entity.ID,
		"properties": entity.Properties,
		"logIndex":   entity.EvidenceLogIndex,
	}
	result, err := session.Run(ctx, cypher, params)
	if err != nil {
		return err
	}
	_, err = result.Consume(ctx)
	return err
}

// UpsertEdge creates or updates an edge between two entities.
func (w *Writer) UpsertEdge(ctx context.Context, edge EdgeRecord) error {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	cypher := fmt.Sprintf(`
		MATCH (from:%s {id: $fromID})
		MATCH (to:%s {id: $toID})
		MERGE (from)-[:%s]->(to)
	`, edge.FromLabel, edge.ToLabel, edge.EdgeType)

	params := map[string]any{
		"fromID": edge.FromID,
		"toID":   edge.ToID,
	}
	result, err := session.Run(ctx, cypher, params)
	if err != nil {
		return err
	}
	_, err = result.Consume(ctx)
	return err
}

// ThreatModel assembles the threat model for a subject by traversing from Subject
// through Evidence to defined entities and their relationships.
func (w *Writer) ThreatModel(ctx context.Context, subjectID string) (*ThreatModelResult, error) {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result := &ThreatModelResult{
		SubjectID:    subjectID,
		Capabilities: []ThreatModelCapability{},
		Threats:      []ThreatModelThreat{},
		Controls:     []ThreatModelControl{},
		Vectors:      []ThreatModelVector{},
	}

	// Get capabilities with their evidence source
	capCypher := `
		MATCH (s:Subject {id: $subjectID})<-[:TARGETS]-(e:Evidence)-[:DEFINES]->(c:Capability)
		MATCH (e)-[:PUBLISHED_BY]->(p:Publisher)
		RETURN c.id AS id, c.title AS title, c.description AS description,
		       e.logIndex AS logIndex, e.digest AS digest, e.sealed AS sealed,
		       p.issuer AS issuer, p.sub AS sub
	`
	capResult, err := session.Run(ctx, capCypher, map[string]any{"subjectID": subjectID})
	if err != nil {
		return nil, err
	}

	capMap := make(map[string]*ThreatModelCapability)
	for capResult.Next(ctx) {
		rec := capResult.Record()
		id, _ := rec.Get("id")
		title, _ := rec.Get("title")
		description, _ := rec.Get("description")
		logIndex, _ := rec.Get("logIndex")
		digest, _ := rec.Get("digest")
		sealed, _ := rec.Get("sealed")
		issuer, _ := rec.Get("issuer")
		sub, _ := rec.Get("sub")

		cap := ThreatModelCapability{
			Id:          id.(string),
			Title:       toString(title),
			Description: toString(description),
			Introduces:  []string{},
			Source: EvidenceSource{
				LogIndex: logIndex.(int64),
				Digest:   digest.(string),
				Sealed:   toTime(sealed),
				Publisher: PublisherIdentity{
					Issuer: issuer.(string),
					Sub:    sub.(string),
				},
			},
		}
		capMap[cap.Id] = &cap
	}

	// Get INTRODUCES edges
	introCypher := `
		MATCH (c:Capability)-[:INTRODUCES]->(t:Threat)
		WHERE c.id IN $capIDs
		RETURN c.id AS capID, t.id AS threatID
	`
	capIDs := make([]string, 0, len(capMap))
	for id := range capMap {
		capIDs = append(capIDs, id)
	}
	if len(capIDs) > 0 {
		introResult, err := session.Run(ctx, introCypher, map[string]any{"capIDs": capIDs})
		if err != nil {
			return nil, err
		}
		for introResult.Next(ctx) {
			rec := introResult.Record()
			capID, _ := rec.Get("capID")
			threatID, _ := rec.Get("threatID")
			capMap[capID.(string)].Introduces = append(capMap[capID.(string)].Introduces, threatID.(string))
		}
	}

	for _, cap := range capMap {
		result.Capabilities = append(result.Capabilities, *cap)
	}

	// Get threats with their evidence source
	threatCypher := `
		MATCH (s:Subject {id: $subjectID})<-[:TARGETS]-(e:Evidence)-[:DEFINES]->(t:Threat)
		MATCH (e)-[:PUBLISHED_BY]->(p:Publisher)
		RETURN t.id AS id, t.title AS title, t.description AS description,
		       e.logIndex AS logIndex, e.digest AS digest, e.sealed AS sealed,
		       p.issuer AS issuer, p.sub AS sub
	`
	threatResult, err := session.Run(ctx, threatCypher, map[string]any{"subjectID": subjectID})
	if err != nil {
		return nil, err
	}

	threatMap := make(map[string]*ThreatModelThreat)
	for threatResult.Next(ctx) {
		rec := threatResult.Record()
		id, _ := rec.Get("id")
		title, _ := rec.Get("title")
		description, _ := rec.Get("description")
		logIndex, _ := rec.Get("logIndex")
		digest, _ := rec.Get("digest")
		sealed, _ := rec.Get("sealed")
		issuer, _ := rec.Get("issuer")
		sub, _ := rec.Get("sub")

		threat := ThreatModelThreat{
			Id:          id.(string),
			Title:       toString(title),
			Description: toString(description),
			AddressedBy: []string{},
			Leverages:   []string{},
			Source: EvidenceSource{
				LogIndex: logIndex.(int64),
				Digest:   digest.(string),
				Sealed:   toTime(sealed),
				Publisher: PublisherIdentity{
					Issuer: issuer.(string),
					Sub:    sub.(string),
				},
			},
		}
		threatMap[threat.Id] = &threat
	}

	// Get ADDRESSES edges (from controls to threats)
	if len(threatMap) > 0 {
		threatIDs := make([]string, 0, len(threatMap))
		for id := range threatMap {
			threatIDs = append(threatIDs, id)
		}
		addressCypher := `
			MATCH (ctrl:Control)-[:APPLIES]->(t:Threat)
			WHERE t.id IN $threatIDs
			RETURN t.id AS threatID, ctrl.id AS controlID
		`
		addressResult, err := session.Run(ctx, addressCypher, map[string]any{"threatIDs": threatIDs})
		if err != nil {
			return nil, err
		}
		for addressResult.Next(ctx) {
			rec := addressResult.Record()
			threatID, _ := rec.Get("threatID")
			controlID, _ := rec.Get("controlID")
			threatMap[threatID.(string)].AddressedBy = append(threatMap[threatID.(string)].AddressedBy, controlID.(string))
		}

		// Get LEVERAGES edges (threats to capabilities)
		leverageCypher := `
			MATCH (t:Threat)-[:LEVERAGES]->(c:Capability)
			WHERE t.id IN $threatIDs
			RETURN t.id AS threatID, c.id AS capID
		`
		leverageResult, err := session.Run(ctx, leverageCypher, map[string]any{"threatIDs": threatIDs})
		if err != nil {
			return nil, err
		}
		for leverageResult.Next(ctx) {
			rec := leverageResult.Record()
			threatID, _ := rec.Get("threatID")
			capID, _ := rec.Get("capID")
			threatMap[threatID.(string)].Leverages = append(threatMap[threatID.(string)].Leverages, capID.(string))
		}
	}

	for _, threat := range threatMap {
		result.Threats = append(result.Threats, *threat)
	}

	// Get controls with their evidence source
	controlCypher := `
		MATCH (s:Subject {id: $subjectID})<-[:TARGETS]-(e:Evidence)-[:DEFINES]->(c:Control)
		MATCH (e)-[:PUBLISHED_BY]->(p:Publisher)
		RETURN c.id AS id, c.title AS title, c.objective AS objective,
		       c.assessmentRequirements AS assessmentRequirements,
		       e.logIndex AS logIndex, e.digest AS digest, e.sealed AS sealed,
		       p.issuer AS issuer, p.sub AS sub
	`
	controlResult, err := session.Run(ctx, controlCypher, map[string]any{"subjectID": subjectID})
	if err != nil {
		return nil, err
	}

	controlMap := make(map[string]*ThreatModelControl)
	for controlResult.Next(ctx) {
		rec := controlResult.Record()
		id, _ := rec.Get("id")
		title, _ := rec.Get("title")
		objective, _ := rec.Get("objective")
		assessReq, _ := rec.Get("assessmentRequirements")
		logIndex, _ := rec.Get("logIndex")
		digest, _ := rec.Get("digest")
		sealed, _ := rec.Get("sealed")
		issuer, _ := rec.Get("issuer")
		sub, _ := rec.Get("sub")

		control := ThreatModelControl{
			Id:                     id.(string),
			Title:                  toString(title),
			Objective:              toString(objective),
			AssessmentRequirements: toStringSlice(assessReq),
			Applies:                []string{},
			Source: EvidenceSource{
				LogIndex: logIndex.(int64),
				Digest:   digest.(string),
				Sealed:   toTime(sealed),
				Publisher: PublisherIdentity{
					Issuer: issuer.(string),
					Sub:    sub.(string),
				},
			},
		}
		controlMap[control.Id] = &control
	}

	// Get APPLIES edges
	if len(controlMap) > 0 {
		controlIDs := make([]string, 0, len(controlMap))
		for id := range controlMap {
			controlIDs = append(controlIDs, id)
		}
		appliesCypher := `
			MATCH (c:Control)-[:APPLIES]->(t:Threat)
			WHERE c.id IN $controlIDs
			RETURN c.id AS controlID, t.id AS threatID
		`
		appliesResult, err := session.Run(ctx, appliesCypher, map[string]any{"controlIDs": controlIDs})
		if err != nil {
			return nil, err
		}
		for appliesResult.Next(ctx) {
			rec := appliesResult.Record()
			controlID, _ := rec.Get("controlID")
			threatID, _ := rec.Get("threatID")
			controlMap[controlID.(string)].Applies = append(controlMap[controlID.(string)].Applies, threatID.(string))
		}
	}

	for _, control := range controlMap {
		result.Controls = append(result.Controls, *control)
	}

	// Get vectors (no edges for now, just collect them)
	vectorCypher := `
		MATCH (s:Subject {id: $subjectID})<-[:TARGETS]-(e:Evidence)-[:DEFINES]->(v:Vector)
		RETURN v.id AS id, v.title AS title, v.description AS description
	`
	vectorResult, err := session.Run(ctx, vectorCypher, map[string]any{"subjectID": subjectID})
	if err != nil {
		return nil, err
	}
	for vectorResult.Next(ctx) {
		rec := vectorResult.Record()
		id, _ := rec.Get("id")
		title, _ := rec.Get("title")
		description, _ := rec.Get("description")

		result.Vectors = append(result.Vectors, ThreatModelVector{
			Id:          id.(string),
			Title:       toString(title),
			Description: toString(description),
		})
	}
	if err = vectorResult.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// SubjectSummary returns summary statistics for a subject.
func (w *Writer) SubjectSummary(ctx context.Context, subjectID string) (*SubjectSummaryResult, error) {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	cypher := `
		MATCH (s:Subject {id: $subjectID})<-[:TARGETS]-(e:Evidence)-[:PUBLISHED_BY]->(p:Publisher)
		RETURN count(DISTINCT e) AS evidenceCount,
		       count(DISTINCT p) AS publisherCount,
		       e.artifactType AS artifactType,
		       max(e.sealed) AS lastUpdated,
		       count(e) AS typeCount
		ORDER BY artifactType
	`
	result, err := session.Run(ctx, cypher, map[string]any{"subjectID": subjectID})
	if err != nil {
		return nil, err
	}

	summary := &SubjectSummaryResult{
		SubjectID:     subjectID,
		ArtifactTypes: make(map[string]ArtifactTypeSummary),
	}

	firstRow := true
	for result.Next(ctx) {
		rec := result.Record()
		if firstRow {
			evidenceCount, _ := rec.Get("evidenceCount")
			publisherCount, _ := rec.Get("publisherCount")
			summary.EvidenceCount = evidenceCount.(int64)
			summary.PublisherCount = int(publisherCount.(int64))
			firstRow = false
		}

		artifactType, _ := rec.Get("artifactType")
		lastUpdated, _ := rec.Get("lastUpdated")
		typeCount, _ := rec.Get("typeCount")

		if artifactType != nil {
			summary.ArtifactTypes[artifactType.(string)] = ArtifactTypeSummary{
				Count:       typeCount.(int64),
				LastUpdated: toTime(lastUpdated),
			}
		}
	}

	return summary, nil
}

// ListSubjects returns all subjects with their summary statistics.
func (w *Writer) ListSubjects(ctx context.Context) ([]SubjectSummaryResult, error) {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	cypher := `
		MATCH (s:Subject)
		OPTIONAL MATCH (s)<-[:TARGETS]-(e:Evidence)-[:PUBLISHED_BY]->(p:Publisher)
		RETURN s.id AS subjectID,
		       count(DISTINCT e) AS evidenceCount,
		       count(DISTINCT p) AS publisherCount,
		       collect(DISTINCT {type: e.artifactType, sealed: e.sealed}) AS artifacts
	`
	result, err := session.Run(ctx, cypher, nil)
	if err != nil {
		return nil, err
	}

	var subjects []SubjectSummaryResult
	for result.Next(ctx) {
		rec := result.Record()
		subjectID, _ := rec.Get("subjectID")
		evidenceCount, _ := rec.Get("evidenceCount")
		publisherCount, _ := rec.Get("publisherCount")
		artifacts, _ := rec.Get("artifacts")

		summary := SubjectSummaryResult{
			SubjectID:      subjectID.(string),
			EvidenceCount:  evidenceCount.(int64),
			PublisherCount: int(publisherCount.(int64)),
			ArtifactTypes:  make(map[string]ArtifactTypeSummary),
		}

		// Process artifact type summaries
		if artifacts != nil {
			artList := artifacts.([]any)
			typeMap := make(map[string][]time.Time)
			for _, art := range artList {
				artMap := art.(map[string]any)
				if artType, ok := artMap["type"]; ok && artType != nil {
					typeName := artType.(string)
					if sealed, ok := artMap["sealed"]; ok && sealed != nil {
						typeMap[typeName] = append(typeMap[typeName], toTime(sealed))
					}
				}
			}
			for typeName, times := range typeMap {
				var maxTime time.Time
				for _, t := range times {
					if t.After(maxTime) {
						maxTime = t
					}
				}
				summary.ArtifactTypes[typeName] = ArtifactTypeSummary{
					Count:       int64(len(times)),
					LastUpdated: maxTime,
				}
			}
		}

		subjects = append(subjects, summary)
	}

	return subjects, nil
}

// Evidence returns a paginated list of evidence for a subject with optional filtering.
func (w *Writer) Evidence(ctx context.Context, subjectID string, filter EvidenceFilter) (*EvidenceResult, error) {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Build filter conditions
	whereClauses := []string{"s.id = $subjectID"}
	params := map[string]any{"subjectID": subjectID}

	if filter.ArtifactType != nil {
		whereClauses = append(whereClauses, "e.artifactType = $artifactType")
		params["artifactType"] = *filter.ArtifactType
	}

	if filter.Since != nil {
		whereClauses = append(whereClauses, "e.sealed >= $since")
		params["since"] = *filter.Since
	}

	if filter.Before != nil {
		whereClauses = append(whereClauses, "e.sealed < $before")
		params["before"] = *filter.Before
	}

	var cursorLogIndex int64
	if filter.Cursor != nil {
		decoded, err := base64.StdEncoding.DecodeString(*filter.Cursor)
		if err == nil {
			cursorLogIndex, _ = strconv.ParseInt(string(decoded), 10, 64)
			whereClauses = append(whereClauses, "e.logIndex > $cursorIndex")
			params["cursorIndex"] = cursorLogIndex
		}
	}

	limit := 20
	if filter.Limit != nil && *filter.Limit > 0 {
		limit = *filter.Limit
	}
	params["limit"] = limit + 1 // Fetch one extra to determine if there's a next page

	whereClause := whereClauses[0]
	for i := 1; i < len(whereClauses); i++ {
		whereClause += " AND " + whereClauses[i]
	}

	cypher := fmt.Sprintf(`
		MATCH (s:Subject)<-[:TARGETS]-(e:Evidence)-[:PUBLISHED_BY]->(p:Publisher)
		WHERE %s
		RETURN e.logIndex AS logIndex, e.digest AS digest, e.artifactType AS artifactType,
		       e.status AS status, e.sealed AS sealed,
		       p.issuer AS issuer, p.sub AS sub
		ORDER BY e.logIndex
		LIMIT $limit
	`, whereClause)

	result, err := session.Run(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	evidenceResult := &EvidenceResult{
		SubjectID: subjectID,
		Evidence:  []EvidenceItem{},
	}

	var items []EvidenceItem
	for result.Next(ctx) {
		rec := result.Record()
		logIndex, _ := rec.Get("logIndex")
		digest, _ := rec.Get("digest")
		artifactType, _ := rec.Get("artifactType")
		status, _ := rec.Get("status")
		sealed, _ := rec.Get("sealed")
		issuer, _ := rec.Get("issuer")
		sub, _ := rec.Get("sub")

		items = append(items, EvidenceItem{
			LogIndex:     logIndex.(int64),
			Digest:       digest.(string),
			ArtifactType: artifactType.(string),
			Status:       status.(string),
			Sealed:       toTime(sealed),
			Publisher: PublisherIdentity{
				Issuer: issuer.(string),
				Sub:    sub.(string),
			},
		})
	}

	// Check if there's a next page
	if len(items) > limit {
		evidenceResult.Evidence = items[:limit]
		lastItem := items[limit-1]
		nextCursor := base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(lastItem.LogIndex, 10)))
		evidenceResult.NextCursor = &nextCursor
	} else {
		evidenceResult.Evidence = items
	}

	return evidenceResult, nil
}

// Coverage returns coverage statistics for a catalog within a subject.
func (w *Writer) Coverage(ctx context.Context, subjectID, catalogID string) (*CoverageResult, error) {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Get all controls for the catalog
	controlCypher := `
		MATCH (s:Subject {id: $subjectID})<-[:TARGETS]-(e:Evidence)-[:DEFINES]->(c:Control)
		WHERE c.catalogID = $catalogID
		RETURN c.id AS id, c.title AS title
	`
	controlResult, err := session.Run(ctx, controlCypher, map[string]any{
		"subjectID": subjectID,
		"catalogID": catalogID,
	})
	if err != nil {
		return nil, err
	}

	type controlInfo struct {
		id    string
		title string
	}
	var controls []controlInfo
	for controlResult.Next(ctx) {
		rec := controlResult.Record()
		id, _ := rec.Get("id")
		title, _ := rec.Get("title")
		controls = append(controls, controlInfo{
			id:    id.(string),
			title: toString(title),
		})
	}

	// Get coverage information (findings that EVALUATE each control)
	coverageCypher := `
		MATCH (s:Subject {id: $subjectID})<-[:TARGETS]-(e:Evidence)-[:DEFINES]->(f:EvaluationFinding)-[:EVALUATES]->(c:Control)
		WHERE c.catalogID = $catalogID
		RETURN c.id AS controlID, max(e.sealed) AS latestEvidence
	`
	coverageResultQuery, err := session.Run(ctx, coverageCypher, map[string]any{
		"subjectID": subjectID,
		"catalogID": catalogID,
	})
	if err != nil {
		return nil, err
	}

	coveredMap := make(map[string]*time.Time)
	for coverageResultQuery.Next(ctx) {
		rec := coverageResultQuery.Record()
		controlID, _ := rec.Get("controlID")
		latestEvidence, _ := rec.Get("latestEvidence")
		if latestEvidence != nil {
			t := toTime(latestEvidence)
			coveredMap[controlID.(string)] = &t
		}
	}

	// Build result
	result := &CoverageResult{
		SubjectID:   subjectID,
		Catalog:     catalogID,
		CatalogType: "ControlCatalog", // TODO: infer from evidence or make configurable
		Controls:    []CoverageControl{},
		Total:       len(controls),
		Covered:     len(coveredMap),
	}

	for _, ctrl := range controls {
		status := Uncovered
		var latestEvidence *time.Time
		if t, ok := coveredMap[ctrl.id]; ok {
			status = Covered
			latestEvidence = t
		}

		result.Controls = append(result.Controls, CoverageControl{
			Id:             ctrl.id,
			Title:          ctrl.title,
			Status:         status,
			LatestEvidence: latestEvidence,
		})
	}

	return result, nil
}

// Helper functions

func toString(val any) string {
	if val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

func toTime(val any) time.Time {
	if val == nil {
		return time.Time{}
	}
	if t, ok := val.(time.Time); ok {
		return t
	}
	// Handle neo4j LocalDateTime
	if ldt, ok := val.(neo4j.LocalDateTime); ok {
		return ldt.Time()
	}
	return time.Time{}
}

func toStringSlice(val any) []string {
	if val == nil {
		return []string{}
	}
	if slice, ok := val.([]any); ok {
		result := make([]string, 0, len(slice))
		for _, item := range slice {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return []string{}
}
