# SQLite Schema — ids.db

One SQLite database file at the workspace root (`ids.db`). It is shared:
`utils/sessions.py` owns `targets` / `sessions` / `notes`, and
`daharness/findings.py` owns `findings`. Concurrent access from the gateway,
secretary, and MCP clients is handled with busy-timeout + retry inside
`daharness/findings.py`.

## targets            (utils/sessions.py)

| Column     | Type    | Notes                          |
|------------|---------|--------------------------------|
| id         | INTEGER | PRIMARY KEY                    |
| ip_address | TEXT    |                                |
| port       | INTEGER |                                |
| status     | TEXT    | inserted as `'active'`         |

## sessions           (utils/sessions.py)

| Column     | Type     | Notes                                   |
|------------|----------|-----------------------------------------|
| id         | INTEGER  | PRIMARY KEY                             |
| target_id  | INTEGER  | FK → targets.id                         |
| payload    | TEXT     | payload name — plain column, **not** a separate PAYLOADS table |
| status     | TEXT     | inserted as `'active'`                  |
| start_time | DATETIME | CURRENT_TIMESTAMP on insert             |
| end_time   | DATETIME | nullable                                |
| note       | TEXT     | nullable                                |

## notes              (utils/sessions.py)

| Column    | Type    | Notes           |
|-----------|---------|-----------------|
| id        | INTEGER | PRIMARY KEY     |
| target_id | INTEGER | FK → targets.id |
| note      | TEXT    |                 |

## findings           (daharness/findings.py)

| Column        | Type | Notes                                                          |
|---------------|------|----------------------------------------------------------------|
| id            | TEXT | PRIMARY KEY — sequential `F-0001`-style id, IntegrityError-safe |
| title         | TEXT | NOT NULL                                                        |
| severity      | TEXT | NOT NULL — P1–P4                                                |
| cwe           | TEXT | optional                                                        |
| asset         | TEXT | NOT NULL                                                        |
| evidence      | TEXT | JSON (request/response/excerpt)                                 |
| repro         | TEXT | JSON list of reproduction steps                                 |
| tool_chain    | TEXT | JSON list of tools used                                         |
| memory_ref    | TEXT | one-line vector-memory pointer (full finding never enters LLM context) |
| ts            | TEXT | NOT NULL — UTC ISO-8601                                         |
| status        | TEXT | NOT NULL DEFAULT `'open'` — `open` → `closed` / `false_positive` / `duplicate` / `superseded` |
| superseded_by | TEXT | added by migration                                              |
| closed_by     | TEXT | added by migration                                              |
| closed_reason | TEXT | added by migration                                              |
| closed_ts     | TEXT | added by migration                                              |

Migrations: pre-existing tables get lifecycle columns via idempotent
`ALTER TABLE` (column list checked through `PRAGMA table_info`) — see
`FindingStore._init_table`.