
        CREATE TABLE IF NOT EXISTS admins (
          username TEXT PRIMARY KEY, password TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('owner','operator','viewer')));
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
          expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS login_attempts (
          address TEXT PRIMARY KEY, attempts INTEGER NOT NULL, until INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, credential TEXT NOT NULL, name TEXT UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          quota INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
          expires INTEGER, token TEXT UNIQUE NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS nodes (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
          token TEXT UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          last_seen INTEGER, applied_revision TEXT, error TEXT);
        CREATE TABLE IF NOT EXISTS inbounds (
          id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
          name TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL,
          settings TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          UNIQUE(node_id,port));
        CREATE TABLE IF NOT EXISTS counters (
          node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
          epoch TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          up INTEGER NOT NULL, down INTEGER NOT NULL,
          PRIMARY KEY(node_id,epoch,user_id));
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
          actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
