-- Threat-intelligence knowledge base (CTI pack). Postgres is the source of truth;
-- Neo4j holds a best-effort (:CtiObject)-[:CTI_REL]-> projection for graph reads.
CREATE TABLE cti_objects (
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id UUID NOT NULL,
    kind VARCHAR(32) NOT NULL CHECK (kind IN ('actor','identity','infrastructure','malware','indicator','campaign','victim','lead','watch','enrichment','disclosure')),
    name VARCHAR(512) NOT NULL,
    natural_key VARCHAR(1024) NOT NULL,
    status VARCHAR(64) NOT NULL,
    tlp VARCHAR(16) NOT NULL CHECK (tlp IN ('clear','green','amber','amber+strict','red')),
    confidence SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    description TEXT NOT NULL DEFAULT '',
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    labels JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    source VARCHAR(256) NOT NULL DEFAULT 'manual',
    revision BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (owner_id, id),
    UNIQUE (owner_id, kind, natural_key)
);
CREATE INDEX idx_cti_objects_owner_kind_updated ON cti_objects (owner_id, kind, updated_at DESC);

CREATE TABLE cti_relationships (
    owner_id BIGINT NOT NULL,
    id UUID NOT NULL,
    source_id UUID NOT NULL,
    target_id UUID NOT NULL,
    type VARCHAR(64) NOT NULL,
    confidence SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    description TEXT NOT NULL DEFAULT '',
    tlp VARCHAR(16) NOT NULL CHECK (tlp IN ('clear','green','amber','amber+strict','red')),
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    source VARCHAR(256) NOT NULL DEFAULT 'manual',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (owner_id, id),
    UNIQUE (owner_id, source_id, target_id, type),
    CHECK (source_id <> target_id),
    FOREIGN KEY (owner_id, source_id) REFERENCES cti_objects (owner_id, id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id, target_id) REFERENCES cti_objects (owner_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_cti_relationships_target ON cti_relationships (owner_id, target_id);

-- Append-only change journal behind "What changed?" and per-object history.
CREATE TABLE cti_changes (
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    seq BIGSERIAL NOT NULL,
    object_id UUID,
    kind VARCHAR(32) NOT NULL,
    name VARCHAR(512) NOT NULL,
    action VARCHAR(32) NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    source VARCHAR(256) NOT NULL,
    at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (owner_id, seq)
);
CREATE INDEX idx_cti_changes_owner_at ON cti_changes (owner_id, at DESC);
CREATE INDEX idx_cti_changes_object ON cti_changes (owner_id, object_id, at DESC);
