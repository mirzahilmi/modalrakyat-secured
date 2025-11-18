-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
CREATE TABLE documents
(
    id         TEXT PRIMARY KEY NOT NULL,
    filename   TEXT             NOT NULL,
    metadata   jsonb            NOT NULL,
    created_by TEXT             NOT NULL,
    created_at TIMESTAMP        NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
DROP TABLE documents;
-- +goose StatementEnd
