-- CTI pack, second release: inferred relationships, sightings (indicator scoring and
-- decay), analyst notes and opinions, and TAXII 2.1 collections, tokens and feeds.

-- NULL for analyst/ingest edges; the rule id for edges the inference engine derived.
ALTER TABLE cti_relationships ADD COLUMN inferred_by VARCHAR(64);

CREATE TABLE cti_notes (
    owner_id BIGINT NOT NULL,
    id UUID NOT NULL,
    object_id UUID NOT NULL,
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('note','opinion')),
    opinion VARCHAR(32) CHECK (opinion IN ('strongly-disagree','disagree','neutral','agree','strongly-agree')),
    body TEXT NOT NULL,
    tlp VARCHAR(16) NOT NULL CHECK (tlp IN ('clear','green','amber','amber+strict','red')),
    revision BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (owner_id, id),
    CHECK ((kind = 'opinion') = (opinion IS NOT NULL)),
    FOREIGN KEY (owner_id, object_id) REFERENCES cti_objects (owner_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_cti_notes_object ON cti_notes (owner_id, object_id, created_at DESC);

CREATE TABLE cti_sightings (
    owner_id BIGINT NOT NULL,
    id UUID NOT NULL,
    object_id UUID NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    count INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
    where_sighted VARCHAR(256) NOT NULL DEFAULT '',
    source VARCHAR(256) NOT NULL DEFAULT 'manual',
    confidence SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    description TEXT NOT NULL DEFAULT '',
    observed JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (owner_id, id),
    CHECK (first_seen <= last_seen),
    FOREIGN KEY (owner_id, object_id) REFERENCES cti_objects (owner_id, id) ON DELETE CASCADE
);
-- The same report of the same sighting is idempotent (watches resend batches).
CREATE UNIQUE INDEX uq_cti_sightings_report ON cti_sightings (owner_id, object_id, where_sighted, source, first_seen, last_seen);
CREATE INDEX idx_cti_sightings_object ON cti_sightings (owner_id, object_id, last_seen DESC);

-- A collection is a TLP-capped view of one owner's knowledge base served over TAXII 2.1.
CREATE TABLE cti_taxii_collections (
    id UUID PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(256) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    tlp_ceiling VARCHAR(16) NOT NULL CHECK (tlp_ceiling IN ('clear','green','amber','amber+strict','red')),
    include_victims BOOLEAN NOT NULL DEFAULT FALSE,
    can_read BOOLEAN NOT NULL DEFAULT TRUE,
    can_write BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_cti_taxii_collections_owner ON cti_taxii_collections (owner_id);

-- Partner credentials for one collection. Only the SHA-256 of the secret is stored.
CREATE TABLE cti_taxii_tokens (
    id UUID PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    collection_id UUID NOT NULL REFERENCES cti_taxii_collections(id) ON DELETE CASCADE,
    label VARCHAR(256) NOT NULL,
    secret_sha256 BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

-- Remote TAXII collections this owner pulls from. The password is AES-GCM sealed
-- with modulo.remote.credential-key and never returned.
CREATE TABLE cti_taxii_feeds (
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id UUID NOT NULL,
    title VARCHAR(256) NOT NULL,
    api_root VARCHAR(2048) NOT NULL,
    collection_id VARCHAR(256) NOT NULL,
    username VARCHAR(256),
    secret BYTEA,
    default_tlp VARCHAR(16) NOT NULL CHECK (default_tlp IN ('clear','green','amber','amber+strict','red')),
    poll_minutes INTEGER CHECK (poll_minutes IS NULL OR poll_minutes BETWEEN 15 AND 10080),
    added_after VARCHAR(64),
    last_polled_at TIMESTAMPTZ,
    last_result TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (owner_id, id)
);
