use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use postgres::config::{Host, SslMode};
use postgres::error::SqlState;
use postgres::{Client, Config};
use postgres_native_tls::MakeTlsConnector;

/// Connection options from the command line. Unset fields fall back to the
/// libpq environment variables, then to libpq's defaults.
#[derive(Default)]
pub struct Opts {
    pub conninfo: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub dbname: Option<String>,
}

pub fn build_config(opts: &Opts) -> Result<Config> {
    let mut cfg = match &opts.conninfo {
        Some(s) => s.parse::<Config>().context("invalid connection string")?,
        None => Config::new(),
    };
    if let Some(h) = &opts.host {
        cfg.host(h);
    }
    if let Some(p) = opts.port {
        cfg.port(p);
    }
    if let Some(u) = &opts.user {
        cfg.user(u);
    }
    if let Some(d) = &opts.dbname {
        cfg.dbname(d);
    }

    if cfg.get_ports().is_empty() {
        let port = match env::var("PGPORT") {
            Ok(p) => p.parse().context("invalid PGPORT")?,
            Err(_) => 5432,
        };
        cfg.port(port);
    }
    if cfg.get_hosts().is_empty() {
        let port = cfg.get_ports()[0];
        let host = env::var("PGHOST").ok().unwrap_or_else(|| default_host(port));
        cfg.host(&host);
    }
    if cfg.get_user().is_none() {
        let user = env::var("PGUSER")
            .or_else(|_| env::var("USER"))
            .context("no user: pass -U or set PGUSER")?;
        cfg.user(&user);
    }
    if cfg.get_dbname().is_none() {
        cfg.dbname(&env::var("PGDATABASE").unwrap_or_else(|_| "postgres".into()));
    }
    if cfg.get_password().is_none()
        && let Ok(pw) = env::var("PGPASSWORD")
    {
        cfg.password(pw);
    }
    let explicit_ssl = opts.conninfo.as_deref().is_some_and(|s| s.contains("sslmode"));
    if !explicit_ssl && let Ok(mode) = env::var("PGSSLMODE") {
        cfg.ssl_mode(match mode.as_str() {
            "disable" => SslMode::Disable,
            "allow" | "prefer" => SslMode::Prefer,
            "require" => SslMode::Require,
            other => bail!("PGSSLMODE={other} is not supported (pga does not verify server certificates)"),
        });
    }
    cfg.application_name("pga");
    cfg.connect_timeout(Duration::from_secs(10));
    Ok(cfg)
}

/// libpq connects over a Unix socket when no host is given. The socket
/// directory is a compile-time default of the server build, so probe the
/// common ones.
fn default_host(port: u16) -> String {
    ["/tmp", "/var/run/postgresql", "/run/postgresql"]
        .iter()
        .find(|dir| Path::new(dir).join(format!(".s.PGSQL.{port}")).exists())
        .map(|dir| dir.to_string())
        .unwrap_or_else(|| "localhost".into())
}

/// One client per database: a Postgres connection is bound to a single
/// database, and schemas and object grants live in that database's catalog.
pub struct Conn {
    base: Config,
    clients: HashMap<String, Client>,
    notices: Arc<Mutex<Vec<String>>>,
}

impl Conn {
    pub fn new(mut base: Config) -> Self {
        let notices = Arc::new(Mutex::new(Vec::new()));
        let sink = notices.clone();
        base.notice_callback(move |n| {
            sink.lock().unwrap().push(format!("{}: {}", n.severity(), n.message()));
        });
        Conn { base, clients: HashMap::new(), notices }
    }

    pub fn initial_db(&self) -> String {
        self.base.get_dbname().unwrap_or("postgres").to_string()
    }

    pub fn user(&self) -> &str {
        self.base.get_user().unwrap_or("")
    }

    pub fn endpoint(&self) -> String {
        let host = match self.base.get_hosts().first() {
            Some(Host::Tcp(h)) => h.clone(),
            Some(Host::Unix(p)) => p.display().to_string(),
            None => String::new(),
        };
        format!("{host}:{}", self.base.get_ports().first().copied().unwrap_or(5432))
    }

    pub fn set_password(&mut self, password: &str) {
        self.base.password(password);
        self.clients.clear();
    }

    pub fn client(&mut self, db: &str) -> Result<&mut Client> {
        if self.clients.get(db).is_some_and(|c| c.is_closed()) {
            self.clients.remove(db);
        }
        match self.clients.entry(db.to_string()) {
            Entry::Occupied(e) => Ok(e.into_mut()),
            Entry::Vacant(e) => {
                let client = connect(&self.base, db).with_context(|| format!("connect to database {db}"))?;
                Ok(e.insert(client))
            }
        }
    }

    pub fn take_notices(&self) -> Vec<String> {
        std::mem::take(&mut *self.notices.lock().unwrap())
    }
}

fn connect(base: &Config, db: &str) -> Result<Client> {
    let mut cfg = base.clone();
    cfg.dbname(db);
    if cfg.get_password().is_none()
        && let Some(pw) = pgpass(&cfg, db)
    {
        cfg.password(pw);
    }
    // Same as libpq sslmode=prefer/require: encrypt, do not verify the certificate.
    let tls = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
    Ok(cfg.connect(MakeTlsConnector::new(tls))?)
}

/// Looks up a password in the libpq password file (`host:port:db:user:password`).
fn pgpass(cfg: &Config, db: &str) -> Option<String> {
    let path = env::var_os("PGPASSFILE")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| Path::new(&h).join(".pgpass")))?;
    let text = std::fs::read_to_string(path).ok()?;
    let host = match cfg.get_hosts().first()? {
        Host::Tcp(h) => h.clone(),
        Host::Unix(_) => "localhost".into(),
    };
    let port = cfg.get_ports().first().copied().unwrap_or(5432).to_string();
    let want = [host.as_str(), port.as_str(), db, cfg.get_user()?];
    text.lines().filter(|l| !l.starts_with('#')).find_map(|line| {
        let f = split_pgpass(line);
        let hit = f.len() == 5 && f[..4].iter().zip(want).all(|(f, w)| f == "*" || f == w);
        hit.then(|| f[4].clone())
    })
}

/// Splits a password file line on unescaped colons; the fifth field runs to
/// the end of the line.
fn split_pgpass(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    fields.last_mut().unwrap().push(n);
                }
            }
            ':' if fields.len() < 5 => fields.push(String::new()),
            _ => fields.last_mut().unwrap().push(c),
        }
    }
    fields
}

pub fn needs_password(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<postgres::Error>().is_some_and(|pe| {
            pe.code() == Some(&SqlState::INVALID_PASSWORD) || pe.to_string().contains("password missing")
        })
    })
}

/// Server error text with DETAIL and HINT, or the error chain for anything else.
pub fn describe(e: &anyhow::Error) -> String {
    for c in e.chain() {
        if let Some(db) = c.downcast_ref::<postgres::Error>().and_then(|pe| pe.as_db_error()) {
            let mut s = format!("{}: {}", db.severity(), db.message());
            if let Some(d) = db.detail() {
                s.push_str(&format!("\nDETAIL: {d}"));
            }
            if let Some(h) = db.hint() {
                s.push_str(&format!("\nHINT: {h}"));
            }
            return s;
        }
    }
    format!("{e:#}")
}

#[cfg(test)]
mod tests {
    use super::split_pgpass;

    #[test]
    fn pgpass_fields() {
        assert_eq!(split_pgpass("h:5432:*:u:p:w"), ["h", "5432", "*", "u", "p:w"]);
        assert_eq!(split_pgpass(r"h\:x:1:d:u:p\\"), ["h:x", "1", "d", "u", r"p\"]);
    }
}
