# Architecture

## Boundaries
Frontend handles presentation and client-side UX validation only. Backend owns validation, hashing, persistence, analysis and risk decisions.

## Scan lifecycle
UPLOADED → VALIDATING → QUEUED → ANALYZING → GENERATING_REPORT → COMPLETED, or FAILED/CANCELLED.

The current local MVP performs the analysis in a background task. Production should replace this with a durable worker queue and isolated analyzer workers.

## Evidence model
Analyzers emit structured facts. The risk engine consumes only those facts. The report keeps facts separate from interpretation. This prevents an AI explanation layer from becoming a source of security truth.

## Future extension
`analyzers/url`, `analyzers/windows`, and `analyzers/documents` can implement a common analyzer contract without changing scan/report models.
