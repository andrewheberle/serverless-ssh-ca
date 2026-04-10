package api

//go:generate npx tsx --tsconfig ../../../../scripts/tsconfig.json ../../../../scripts/export-schema.ts
//go:generate go tool oapi-codegen --config=../../../oapi-codegen.yaml ./openapi.json
