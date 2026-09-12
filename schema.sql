-- 資料・タスク管理台帳 D1 スキーマ
CREATE TABLE IF NOT EXISTS projects (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  color      TEXT,
  ord        INTEGER DEFAULT 0,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS materials (
  id         TEXT PRIMARY KEY,
  title      TEXT NOT NULL,
  project_id TEXT,
  descr      TEXT,
  created_by TEXT,
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS files (
  id           TEXT PRIMARY KEY,
  material_id  TEXT NOT NULL,
  kind         TEXT NOT NULL,          -- 'file' | 'link'
  kv_key       TEXT,                   -- KV key for uploaded blobs
  url          TEXT,                   -- external URL for links
  name         TEXT,
  content_type TEXT,
  size         INTEGER,
  uploaded_by  TEXT,
  at           TEXT
);

CREATE TABLE IF NOT EXISTS notes (
  id          TEXT PRIMARY KEY,
  material_id TEXT NOT NULL,
  author      TEXT,
  text        TEXT,
  at          TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  assignee    TEXT,
  due         TEXT,
  status      TEXT,
  priority    TEXT DEFAULT '通常',
  project_id  TEXT,
  material_id TEXT,
  note        TEXT,
  created_by  TEXT,
  created_at  TEXT,
  updated_at  TEXT
);

-- そば研究・開発
CREATE TABLE IF NOT EXISTS rnd_themes (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  descr      TEXT,
  created_by TEXT,
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS rnd_trials (
  id          TEXT PRIMARY KEY,
  theme_id    TEXT NOT NULL,
  seq         INTEGER,
  ingredients TEXT,           -- JSON: [{name, amount, unit}]
  method      TEXT,
  result      TEXT,
  rating      INTEGER DEFAULT 0,
  created_by  TEXT,
  created_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_files_mat ON files(material_id);
CREATE INDEX IF NOT EXISTS idx_notes_mat ON notes(material_id);
CREATE INDEX IF NOT EXISTS idx_tasks_mat ON tasks(material_id);
CREATE INDEX IF NOT EXISTS idx_trials_theme ON rnd_trials(theme_id);
