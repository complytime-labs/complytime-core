package gateway

import (
	"embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.json
var schemaFS embed.FS

// validationError extends the generated ValidationError with an Error() method.
type validationError struct {
	ValidationError
}

func (e *validationError) Error() string {
	return fmt.Sprintf("validation failed for %s: %s", e.ArtifactType, strings.Join(e.Details, "; "))
}

// newValidationError creates a validationError with pre-populated error message.
func newValidationError(artifactType string, details []string) *validationError {
	ve := &validationError{
		ValidationError: ValidationError{
			ArtifactType: artifactType,
			Details:      details,
		},
	}
	ve.ValidationError.Error = ve.Error()
	return ve
}

// SchemaRegistry holds compiled JSON schemas for Gemara artifact types.
type SchemaRegistry struct {
	schemas map[string]*jsonschema.Schema
}

// NewSchemaRegistry loads and compiles all Gemara JSON schemas.
func NewSchemaRegistry() (*SchemaRegistry, error) {
	// Map Gemara artifact types to schema files
	schemaFiles := map[string]string{
		"EvaluationLog":     "schemas/evaluation-log.json",
		"EnforcementLog":    "schemas/enforcement-log.json",
		"AuditLog":          "schemas/audit-log.json",
		"Policy":            "schemas/policy.json",
		"MappingDocument":   "schemas/mapping-document.json",
		"ControlCatalog":    "schemas/control-catalog.json",
		"CapabilityCatalog": "schemas/capability-catalog.json",
		"GuidanceCatalog":   "schemas/guidance-catalog.json",
		"ThreatCatalog":     "schemas/threat-catalog.json",
		"RiskCatalog":       "schemas/risk-catalog.json",
		"Lexicon":           "schemas/lexicon.json",
		"VectorCatalog":     "schemas/vector-catalog.json",
		"PrincipleCatalog":  "schemas/principle-catalog.json",
	}

	schemas := make(map[string]*jsonschema.Schema)

	// Create one compiler and add all resources to it
	compiler := jsonschema.NewCompiler()

	for _, schemaFile := range schemaFiles {
		schemaBytes, err := schemaFS.ReadFile(schemaFile)
		if err != nil {
			return nil, fmt.Errorf("read schema %s: %w", schemaFile, err)
		}

		var schemaData interface{}
		if err := json.Unmarshal(schemaBytes, &schemaData); err != nil {
			return nil, fmt.Errorf("unmarshal schema %s: %w", schemaFile, err)
		}

		if err := compiler.AddResource(schemaFile, schemaData); err != nil {
			return nil, fmt.Errorf("add schema resource %s: %w", schemaFile, err)
		}
	}

	// Compile all schemas
	for artifactType, schemaFile := range schemaFiles {
		schema, err := compiler.Compile(schemaFile)
		if err != nil {
			return nil, fmt.Errorf("compile schema %s: %w", schemaFile, err)
		}

		schemas[artifactType] = schema
	}

	return &SchemaRegistry{schemas: schemas}, nil
}

// Validate validates a Gemara artifact against its JSON schema.
// Returns nil if valid, *validationError if invalid.
func (r *SchemaRegistry) Validate(artifactBytes []byte) error {
	// Parse the artifact to extract metadata.type
	var artifact map[string]interface{}
	if err := json.Unmarshal(artifactBytes, &artifact); err != nil {
		return newValidationError("unknown", []string{fmt.Sprintf("invalid JSON: %v", err)})
	}

	// Extract artifact type from metadata.type (Gemara convention)
	var metadataType string
	if metadata, ok := artifact["metadata"].(map[string]interface{}); ok {
		if t, ok := metadata["type"].(string); ok {
			metadataType = t
		}
	}

	// If metadata.type is present, this is claiming to be a Gemara artifact
	if metadataType != "" {
		schema, ok := r.schemas[metadataType]
		if !ok {
			// metadata.type present but not recognized - error
			supportedTypes := make([]string, 0, len(r.schemas))
			for t := range r.schemas {
				supportedTypes = append(supportedTypes, t)
			}
			slices.Sort(supportedTypes)
			return newValidationError(metadataType, []string{fmt.Sprintf("unsupported artifact type '%s', supported types: %v", metadataType, supportedTypes)})
		}

		// Validate against schema
		if err := schema.Validate(artifact); err != nil {
			// Extract field-level errors
			var fieldErrors []string
			if ve, ok := err.(*jsonschema.ValidationError); ok {
				fieldErrors = collectValidationErrors(ve)
			} else {
				fieldErrors = []string{err.Error()}
			}

			return newValidationError(metadataType, fieldErrors)
		}

		return nil
	}

	// No metadata.type - check for top-level type (backward compat for non-Gemara artifacts)
	if topLevelType, ok := artifact["type"].(string); ok {
		// Try to validate if it matches a known schema, but don't error if not found
		if schema, ok := r.schemas[topLevelType]; ok {
			if err := schema.Validate(artifact); err != nil {
				// Extract field-level errors
				var fieldErrors []string
				if ve, ok := err.(*jsonschema.ValidationError); ok {
					fieldErrors = collectValidationErrors(ve)
				} else {
					fieldErrors = []string{err.Error()}
				}

				return newValidationError(topLevelType, fieldErrors)
			}
		}
		// Top-level type not in schema registry - skip validation (non-Gemara artifact)
		return nil
	}

	// No type field at all - skip validation (typeless payload like DSSE)
	return nil
}

// collectValidationErrors recursively collects all validation error messages.
func collectValidationErrors(err *jsonschema.ValidationError) []string {
	var errors []string

	// If this error has no causes, it's a leaf error - add it
	if len(err.Causes) == 0 {
		instancePath := strings.Join(err.InstanceLocation, "/")
		if instancePath == "" {
			instancePath = "/"
		}
		// Use the error's Error() method which formats the error message
		errors = append(errors, fmt.Sprintf("%s: %v", instancePath, err.ErrorKind))
	}

	// Recursively collect child errors
	for _, cause := range err.Causes {
		errors = append(errors, collectValidationErrors(cause)...)
	}

	return errors
}
