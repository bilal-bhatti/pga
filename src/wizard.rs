//! Multi-step flows that end in SQL to confirm, or in a navigation outcome.
//! Each flow asks one step at a time; answers are collected in order.

use std::collections::HashSet;

use crate::catalog::{self, Database, DefAcl, Extension, Grant, Member, Role, RoleDep, Schema};
use crate::conn::Conn;

pub struct Ctx<'a> {
    pub roles: &'a [Role],
    pub members: &'a [Member],
    pub schemas: &'a [Schema],
    pub dbs: &'a [Database],
    pub extensions: &'a [Extension],
    /// The connected database; `schemas` and `extensions` belong to it.
    pub db: &'a str,
    pub conn: &'a Conn,
    pub v: i32,
    pub user: &'a str,
    pub keywords: &'a HashSet<String>,
}

/// An object that GRANT/REVOKE/OWNER TO can act on.
#[derive(Clone)]
pub struct Target {
    /// Object type keyword in GRANT, e.g. `SCHEMA`.
    pub what: &'static str,
    /// Object type keyword in ALTER ... OWNER TO.
    pub alter: &'static str,
    pub ident: String,
    pub label: String,
    /// Database to run in; None for cluster-wide objects.
    pub db: Option<String>,
    pub privs: Vec<&'static str>,
    pub grants: Vec<Grant>,
}

pub struct Action {
    pub db: Option<String>,
    /// Shown in the confirm dialog; differs from `exec` only by redacted passwords.
    pub display: Vec<String>,
    pub exec: Vec<String>,
    pub note: Option<String>,
    /// False for a statement that cannot run in a transaction block, e.g. CREATE DATABASE.
    pub transaction: bool,
    /// Flow started after the statements succeed.
    pub then: Option<Box<Flow>>,
}

impl Action {
    fn new(db: Option<String>, stmts: Vec<String>, note: Option<String>) -> Action {
        Action { db, display: stmts.clone(), exec: stmts, note, transaction: true, then: None }
    }

    fn shown_as(mut self, display: Vec<String>) -> Action {
        self.display = display;
        self
    }

    fn outside_transaction(mut self) -> Action {
        self.transaction = false;
        self
    }

    fn followed_by(mut self, flow: Flow) -> Action {
        self.then = Some(Box::new(flow));
        self
    }
}

pub enum Outcome {
    Run(Action),
    UseDb(String),
    /// Text for the clipboard.
    Copy(String),
    /// Why the flow cannot go on, too long for the status line.
    Blocked { title: String, text: String },
}

pub enum Flow {
    UseDb,
    Grant(Target),
    Revoke(Target),
    Owner(Target),
    CreateRole,
    /// Follow-up to CreateRole: database CONNECT and memberships.
    RoleAccess { name: String },
    EditRole(Role),
    Password(Role),
    Join(Role),
    Leave(Role),
    /// `deps` from catalog::role_deps for every database that has some.
    DropRole { role: Role, deps: Vec<RoleDep> },
    /// Per-database statements of a role drop still to run; the last stage holds DROP ROLE.
    DropStages { role: String, stages: Vec<(String, Vec<String>)> },
    CreateDb,
    /// Follow-up to CreateDb: who may connect.
    DbAccess { name: String },
    DefGrant { db: String },
    DefRevoke { db: String, acl: DefAcl, grant: Grant },
    CreateExtension { db: String },
    /// Defaults from the current selection; empty for none.
    Dsn { role: String, schema: String },
}

pub enum StepKind {
    Pick,
    Multi,
    Input { masked: bool },
}

pub struct Opt {
    pub label: String,
    pub value: String,
}

fn opt(label: impl Into<String>, value: impl Into<String>) -> Opt {
    Opt { label: label.into(), value: value.into() }
}

pub struct Step {
    pub title: String,
    pub hint: Option<String>,
    pub kind: StepKind,
    pub opts: Vec<Opt>,
    pub checked: Vec<bool>,
    pub cursor: usize,
    /// Filter text for Pick, the value for Input.
    pub text: String,
}

impl Step {
    fn new(title: impl Into<String>, kind: StepKind, opts: Vec<Opt>, checked: Vec<bool>) -> Step {
        Step { title: title.into(), hint: None, kind, opts, checked, cursor: 0, text: String::new() }
    }

    fn hint(mut self, hint: impl Into<String>) -> Step {
        self.hint = Some(hint.into());
        self
    }

    /// Indices of options shown; Pick filters by the typed text.
    pub fn visible(&self) -> Vec<usize> {
        match self.kind {
            StepKind::Pick => {
                let f = self.text.to_lowercase();
                (0..self.opts.len()).filter(|&i| self.opts[i].label.to_lowercase().contains(&f)).collect()
            }
            _ => (0..self.opts.len()).collect(),
        }
    }

    pub fn answer(&self) -> Option<Vec<String>> {
        match self.kind {
            StepKind::Pick => self.visible().get(self.cursor).map(|&i| vec![self.opts[i].value.clone()]),
            StepKind::Multi => Some(
                self.opts.iter().zip(&self.checked).filter(|(_, c)| **c).map(|(o, _)| o.value.clone()).collect(),
            ),
            StepKind::Input { .. } => Some(vec![self.text.clone()]),
        }
    }
}

fn pick(title: impl Into<String>, opts: Vec<Opt>) -> Next {
    Next::Ask(Step::new(title, StepKind::Pick, opts, Vec::new()))
}

/// A Pick step with the cursor on the option whose value is `default`.
fn pick_at(title: impl Into<String>, opts: Vec<Opt>, default: &str) -> Next {
    let cursor = opts.iter().position(|o| o.value == default).unwrap_or(0);
    Next::Ask(Step { cursor, ..Step::new(title, StepKind::Pick, opts, Vec::new()) })
}

fn multi(title: impl Into<String>, opts: Vec<Opt>, checked: Vec<bool>) -> Step {
    Step::new(title, StepKind::Multi, opts, checked)
}

fn input(title: impl Into<String>, masked: bool) -> Step {
    Step::new(title, StepKind::Input { masked }, Vec::new(), Vec::new())
}

pub enum Next {
    Ask(Step),
    /// The flow does not need this step; record the answer and continue.
    Skip(Vec<String>),
    Done(Outcome),
    Abort(String),
}

pub struct Wizard {
    pub flow: Flow,
    pub answers: Vec<Vec<String>>,
    pub step: Step,
}

const GRANT_OPTION: &str = "WITH GRANT OPTION";
const GRANT_OPTION_FOR: &str = "GRANT OPTION FOR";
const CASCADE: &str = "CASCADE";
const REVOKE_PUBLIC: &str = "REVOKE FROM PUBLIC";
const SEP: char = '\u{1f}';

/// Role attributes as (keyword, explanation, CREATE ROLE default).
const ATTRS: &[(&str, &str, bool)] = &[
    ("LOGIN", "may connect; a role with LOGIN is a user", false),
    ("INHERIT", "uses privileges of roles it belongs to without SET ROLE", true),
    ("CREATEDB", "may create databases", false),
    ("CREATEROLE", "may create, alter and drop roles", false),
    ("REPLICATION", "may stream replication and backups", false),
    ("BYPASSRLS", "ignores row-level security policies", false),
    ("SUPERUSER", "bypasses every permission check", false),
];

fn role_attr(r: &Role, attr: &str) -> bool {
    match attr {
        "LOGIN" => r.login,
        "INHERIT" => r.inherit,
        "CREATEDB" => r.createdb,
        "CREATEROLE" => r.createrole,
        "REPLICATION" => r.replication,
        "BYPASSRLS" => r.bypassrls,
        _ => r.superuser,
    }
}

fn attr_opts() -> Vec<Opt> {
    ATTRS.iter().map(|(k, d, _)| opt(format!("{k:<12} {d}"), *k)).collect()
}

fn role_label(r: &Role) -> String {
    let mut tags = r.attributes();
    if r.login {
        tags.insert(0, "login");
    }
    if tags.is_empty() { r.name.clone() } else { format!("{}  ({})", r.name, tags.join(", ")) }
}

/// Roles as options with their quoted name as value; user roles before pg_* roles.
fn role_opts(ctx: &Ctx, public: bool, exclude: Option<u32>) -> Vec<Opt> {
    let mut roles: Vec<&Role> = ctx.roles.iter().filter(|r| Some(r.oid) != exclude).collect();
    roles.sort_by_key(|r| (r.system(), r.name != ctx.user, r.name.clone()));
    let mut opts = Vec::new();
    if public {
        opts.push(opt("PUBLIC  (every role, including future ones)", "PUBLIC"));
    }
    opts.extend(roles.into_iter().map(|r| opt(role_label(r), r.ident.clone())));
    opts
}

fn priv_opts(privs: &[&str], with_grant_option: bool) -> (Vec<Opt>, Vec<bool>) {
    let mut opts: Vec<Opt> = privs.iter().map(|p| opt(*p, *p)).collect();
    if with_grant_option {
        opts.push(opt("WITH GRANT OPTION  (grantee may grant these on)", GRANT_OPTION));
    }
    let n = opts.len();
    (opts, vec![false; n])
}

/// Splits selected privileges from the WITH GRANT OPTION marker.
fn split_option(answer: &[String], marker: &str) -> (Vec<String>, bool) {
    let flag = answer.iter().any(|a| a == marker);
    (answer.iter().filter(|a| *a != marker && *a != CASCADE).cloned().collect(), flag)
}

fn scram_literal(password: &str) -> String {
    format!("'{}'", postgres_protocol::password::scram_sha_256(password.as_bytes()).replace('\'', "''"))
}

/// REVOKE that clears one privilege entry of catalog::role_deps; None for ownership and policies.
fn revoke_sql(d: &RoleDep, role: &str) -> Option<String> {
    if d.deptype != "a" {
        return None;
    }
    let on = match d.kind.as_str() {
        "table" | "view" | "materialized view" | "foreign table" => "TABLE",
        k if k.ends_with(" column") => {
            return d.column.as_ref().map(|c| format!("REVOKE ALL ({c}) ON TABLE {} FROM {role}", d.ident));
        }
        "default acl" => {
            let (creator, schema, objtype) = d.defacl.as_ref()?;
            let schema = schema.as_ref().map(|s| format!(" IN SCHEMA {s}")).unwrap_or_default();
            return Some(format!(
                "ALTER DEFAULT PRIVILEGES FOR ROLE {creator}{schema} REVOKE ALL ON {} FROM {role}",
                catalog::defacl_keyword(objtype)
            ));
        }
        "sequence" => "SEQUENCE",
        "function" | "aggregate" => "FUNCTION",
        "procedure" => "PROCEDURE",
        "schema" => "SCHEMA",
        "type" => "TYPE",
        "language" => "LANGUAGE",
        "foreign-data wrapper" => "FOREIGN DATA WRAPPER",
        "server" => "FOREIGN SERVER",
        "large object" => "LARGE OBJECT",
        "database" => "DATABASE",
        "tablespace" => "TABLESPACE",
        "parameter ACL" => "PARAMETER",
        _ => return None,
    };
    Some(format!("REVOKE ALL ON {on} {} FROM {role}", d.ident))
}

/// "  (in db)" for an entry outside the connected database.
fn in_db(db: &str, current: &str) -> String {
    if db.is_empty() || db == current { String::new() } else { format!("  (in {db})") }
}

/// Action for the first of `stages`, followed by the rest.
fn drop_stage(role: &str, mut stages: Vec<(String, Vec<String>)>) -> Action {
    let (db, stmts) = stages.remove(0);
    if stages.is_empty() {
        let note = (stmts.len() > 1).then(|| "If DROP ROLE fails, the statements above roll back too.".to_string());
        return Action::new(Some(db), stmts, note);
    }
    let note = format!(
        "Commits on its own. {} more database(s) follow, the last with DROP ROLE {role}; cancelling later keeps this done.",
        stages.len()
    );
    Action::new(Some(db), stmts, Some(note)).followed_by(Flow::DropStages { role: role.into(), stages })
}

/// Options of `grant` (GRANT group TO member). Before PG16 only ADMIN is per membership.
fn membership_step(grant: String, inherit: bool, v: i32) -> Step {
    if v >= 160000 {
        multi(
            format!("{grant}: membership options"),
            vec![
                opt("ADMIN    may grant this membership to others", "ADMIN"),
                opt("INHERIT  uses the role's privileges without SET ROLE", "INHERIT"),
                opt("SET      may SET ROLE to the role", "SET"),
            ],
            vec![false, inherit, true],
        )
    } else {
        multi(format!("{grant}: options"), vec![opt("WITH ADMIN OPTION  may grant this membership to others", "ADMIN")], vec![false])
    }
}

fn membership_sql(groups: &str, member: &str, opts: &[String], v: i32) -> String {
    let on = |k: &str| if opts.iter().any(|x| x == k) { "TRUE" } else { "FALSE" };
    if v >= 160000 {
        format!("GRANT {groups} TO {member} WITH ADMIN {}, INHERIT {}, SET {}", on("ADMIN"), on("INHERIT"), on("SET"))
    } else if on("ADMIN") == "TRUE" {
        format!("GRANT {groups} TO {member} WITH ADMIN OPTION")
    } else {
        format!("GRANT {groups} TO {member}")
    }
}

impl Flow {
    pub fn next(&self, a: &[Vec<String>], ctx: &Ctx) -> Next {
        let n = a.len();
        let one = |i: usize| a[i].first().cloned().unwrap_or_default();
        let run = |db: Option<String>, stmts: Vec<String>, note: Option<String>| {
            Next::Done(Outcome::Run(Action::new(db, stmts, note)))
        };
        match self {
            Flow::UseDb => match n {
                0 => pick(
                    "Use which database?",
                    ctx.dbs.iter().filter(|d| d.allow_conn).map(|d| opt(d.name.clone(), d.name.clone())).collect(),
                ),
                _ => Next::Done(Outcome::UseDb(one(0))),
            },

            Flow::Grant(t) => match n {
                0 => pick(format!("GRANT on {} {}: to which role?", t.what.to_lowercase(), t.label), role_opts(ctx, true, None)),
                1 => {
                    let (opts, checked) = priv_opts(&t.privs, true);
                    Next::Ask(multi(format!("GRANT ... ON {} {} TO {}: which privileges?", t.what, t.label, one(0)), opts, checked))
                }
                _ => {
                    let (privs, go) = split_option(&a[1], GRANT_OPTION);
                    if privs.is_empty() {
                        return Next::Abort("no privilege selected".into());
                    }
                    let go = if go { " WITH GRANT OPTION" } else { "" };
                    let sql = format!("GRANT {} ON {} {} TO {}{go}", privs.join(", "), t.what, t.ident, one(0));
                    run(t.db.clone(), vec![sql], None)
                }
            },

            Flow::Revoke(t) => {
                if t.grants.is_empty() {
                    return Next::Abort(format!("no grants on {}", t.label));
                }
                match n {
                    0 => pick(
                        format!("REVOKE on {} {}: which grant?", t.what.to_lowercase(), t.label),
                        t.grants
                            .iter()
                            .enumerate()
                            .map(|(i, g)| opt(format!("{}: {}  (granted by {})", g.grantee, g.privs_text(), g.grantor), i.to_string()))
                            .collect(),
                    ),
                    1 => {
                        let g = &t.grants[one(0).parse::<usize>().unwrap_or_default()];
                        let mut opts: Vec<Opt> = g.privs.iter().map(|p| opt(p.name.clone(), p.name.clone())).collect();
                        let mut checked = vec![true; opts.len()];
                        opts.push(opt("GRANT OPTION FOR  (keep the privileges, remove only the grant option)", GRANT_OPTION_FOR));
                        opts.push(opt("CASCADE  (also revoke what the grantee granted on)", CASCADE));
                        checked.extend([false, false]);
                        Next::Ask(multi(format!("REVOKE ... FROM {}: which privileges?", g.grantee), opts, checked))
                    }
                    _ => {
                        let g = &t.grants[one(0).parse::<usize>().unwrap_or_default()];
                        let (privs, option_only) = split_option(&a[1], GRANT_OPTION_FOR);
                        if privs.is_empty() {
                            return Next::Abort("no privilege selected".into());
                        }
                        let cascade = if a[1].iter().any(|x| x == CASCADE) { " CASCADE" } else { "" };
                        let prefix = if option_only { "GRANT OPTION FOR " } else { "" };
                        let sql = format!(
                            "REVOKE {prefix}{} ON {} {} FROM {}{cascade}",
                            privs.join(", "),
                            t.what,
                            t.ident,
                            g.grantee_ident
                        );
                        let note = (g.grantor != ctx.user).then(|| {
                            format!(
                                "Granted by {}. REVOKE removes only grants made by the current role (a superuser acts as the \
                                 object owner). Otherwise PostgreSQL warns and changes nothing.",
                                g.grantor
                            )
                        });
                        run(t.db.clone(), vec![sql], note)
                    }
                }
            }

            Flow::Owner(t) => match n {
                0 => pick(format!("New owner of {} {}?", t.what.to_lowercase(), t.label), role_opts(ctx, false, None)),
                _ => run(t.db.clone(), vec![format!("ALTER {} {} OWNER TO {}", t.alter, t.ident, one(0))], None),
            },

            Flow::CreateRole => match n {
                0 => Next::Ask(input("Name of the new role", false)),
                1 => {
                    let checked = ATTRS.iter().map(|(k, _, d)| *k == "LOGIN" || *d).collect();
                    Next::Ask(multi(format!("Attributes of {}", one(0)), attr_opts(), checked))
                }
                2 if a[1].iter().any(|x| x == "LOGIN") => {
                    Next::Ask(input("Password (empty: none)", true).hint("Hashed to SCRAM-SHA-256 here; the plain text is not sent."))
                }
                2 => Next::Skip(vec![String::new()]),
                _ => {
                    let name = one(0);
                    if name.is_empty() {
                        return Next::Abort("empty role name".into());
                    }
                    let mut words: Vec<String> = Vec::new();
                    for (k, _, default) in ATTRS {
                        let on = a[1].iter().any(|x| x == k);
                        if on != *default {
                            words.push(if on { k.to_string() } else { format!("NO{k}") });
                        }
                    }
                    let ident = catalog::quote_ident(&name, ctx.keywords);
                    let mut sql = format!("CREATE ROLE {ident}");
                    if !words.is_empty() {
                        sql.push_str(&format!(" WITH {}", words.join(" ")));
                    }
                    let password = one(2);
                    let action = if password.is_empty() {
                        Action::new(None, vec![sql], None)
                    } else {
                        let sep = if words.is_empty() { " WITH" } else { "" };
                        Action::new(None, vec![format!("{sql}{sep} PASSWORD {}", scram_literal(&password))], None)
                            .shown_as(vec![format!("{sql}{sep} PASSWORD '********'")])
                    };
                    Next::Done(Outcome::Run(action.followed_by(Flow::RoleAccess { name })))
                }
            },

            Flow::RoleAccess { name } => {
                let Some(r) = ctx.roles.iter().find(|r| &r.name == name) else {
                    return Next::Abort(format!("role {name} not found"));
                };
                match n {
                    0 => {
                        let opts: Vec<Opt> = ctx
                            .dbs
                            .iter()
                            .filter(|d| d.allow_conn && !d.template)
                            .map(|d| {
                                let public =
                                    d.grants.iter().any(|g| g.grantee == "PUBLIC" && g.privs.iter().any(|p| p.name == "CONNECT"));
                                let label = if public { format!("{}  (PUBLIC has CONNECT)", d.name) } else { d.name.clone() };
                                opt(label, d.ident.clone())
                            })
                            .collect();
                        let checked = vec![false; opts.len()];
                        Next::Ask(
                            multi(format!("{} created. GRANT CONNECT on which databases?", r.name), opts, checked)
                                .hint("Esc skips the rest; the role exists either way."),
                        )
                    }
                    1 => {
                        let opts = role_opts(ctx, false, Some(r.oid));
                        let checked = vec![false; opts.len()];
                        Next::Ask(multi(format!("Make {} a member of which roles?", r.name), opts, checked))
                    }
                    2 if a[1].is_empty() => Next::Skip(Vec::new()),
                    2 => Next::Ask(membership_step(format!("GRANT {} TO {}", a[1].join(", "), r.name), r.inherit, ctx.v)),
                    _ => {
                        let mut stmts = Vec::new();
                        if !a[0].is_empty() {
                            stmts.push(format!("GRANT CONNECT ON DATABASE {} TO {}", a[0].join(", "), r.ident));
                        }
                        if !a[1].is_empty() {
                            stmts.push(membership_sql(&a[1].join(", "), &r.ident, &a[2], ctx.v));
                        }
                        if stmts.is_empty() {
                            return Next::Abort("nothing selected".into());
                        }
                        run(None, stmts, Some("Schemas and tables inside a database need their own grants.".into()))
                    }
                }
            }

            Flow::EditRole(r) => match n {
                0 => {
                    let checked = ATTRS.iter().map(|(k, _, _)| role_attr(r, k)).collect();
                    Next::Ask(multi(format!("Attributes of {}", r.name), attr_opts(), checked))
                }
                _ => {
                    let changes: Vec<String> = ATTRS
                        .iter()
                        .filter_map(|(k, _, _)| {
                            let on = a[0].iter().any(|x| x == k);
                            (on != role_attr(r, k)).then(|| if on { k.to_string() } else { format!("NO{k}") })
                        })
                        .collect();
                    if changes.is_empty() {
                        return Next::Abort("no change".into());
                    }
                    run(None, vec![format!("ALTER ROLE {} WITH {}", r.ident, changes.join(" "))], None)
                }
            },

            Flow::Password(r) => match n {
                0 => Next::Ask(
                    input(format!("New password for {} (empty: remove the password)", r.name), true)
                        .hint("Hashed to SCRAM-SHA-256 here; the plain text is not sent."),
                ),
                1 if one(0).is_empty() => Next::Skip(vec![String::new()]),
                1 => Next::Ask(input("Repeat the password", true)),
                _ => {
                    let pw = one(0);
                    if pw != one(1) {
                        return Next::Abort("passwords differ".into());
                    }
                    if pw.is_empty() {
                        return run(None, vec![format!("ALTER ROLE {} PASSWORD NULL", r.ident)], None);
                    }
                    Next::Done(Outcome::Run(
                        Action::new(None, vec![format!("ALTER ROLE {} PASSWORD {}", r.ident, scram_literal(&pw))], None)
                            .shown_as(vec![format!("ALTER ROLE {} PASSWORD '********'", r.ident)]),
                    ))
                }
            },

            Flow::Join(r) => match n {
                0 => pick(format!("Make {} a member of which role?", r.name), role_opts(ctx, false, Some(r.oid))),
                1 => Next::Ask(membership_step(format!("GRANT {} TO {}", one(0), r.name), r.inherit, ctx.v)),
                _ => run(None, vec![membership_sql(&one(0), &r.ident, &a[1], ctx.v)], None),
            },

            Flow::Leave(r) => match n {
                0 => {
                    let opts: Vec<Opt> = ctx
                        .members
                        .iter()
                        .filter(|m| m.member == r.oid)
                        .filter_map(|m| {
                            let g = ctx.roles.iter().find(|x| x.oid == m.role)?;
                            Some(opt(
                                format!("{}  (granted by {})", g.name, m.grantor),
                                format!("{}{SEP}{}", g.ident, m.grantor_ident),
                            ))
                        })
                        .collect();
                    if opts.is_empty() {
                        return Next::Abort(format!("{} is not a member of any role", r.name));
                    }
                    pick(format!("Remove {} from which role?", r.name), opts)
                }
                _ => {
                    let v = one(0);
                    let (group, grantor) = v.split_once(SEP).unwrap_or((&v, ""));
                    let sql = if ctx.v >= 160000 {
                        format!("REVOKE {group} FROM {} GRANTED BY {grantor}", r.ident)
                    } else {
                        format!("REVOKE {group} FROM {}", r.ident)
                    };
                    run(None, vec![sql], None)
                }
            },

            Flow::DropRole { role: r, deps } => {
                let blocked: Vec<String> = deps
                    .iter()
                    .filter(|d| revoke_sql(d, "").is_none())
                    .map(|d| {
                        let how = match d.deptype.as_str() {
                            "o" => "owner of",
                            "r" => "target of",
                            _ => "privileges on",
                        };
                        format!("{how} {}{}", d.what, in_db(&d.db, ctx.db))
                    })
                    .collect();
                if !blocked.is_empty() {
                    return Next::Done(Outcome::Blocked {
                        title: format!("{} cannot be dropped yet", r.name),
                        text: format!(
                            "{}\n\nREVOKE does not clear these. Change the owner (o) or the policy first, or run in each \
                             database listed: REASSIGN OWNED BY {1} TO <other role>; DROP OWNED BY {1};",
                            blocked.join("\n"),
                            r.ident
                        ),
                    });
                }
                match n {
                    0 if deps.is_empty() => Next::Skip(Vec::new()),
                    0 => {
                        let mut opts: Vec<Opt> = deps
                            .iter()
                            .enumerate()
                            .filter_map(|(i, d)| {
                                Some(opt(format!("{}{}", revoke_sql(d, &r.ident)?, in_db(&d.db, ctx.db)), i.to_string()))
                            })
                            .collect();
                        let title = format!("{} still holds {} privileges. Revoke before DROP ROLE?", r.name, opts.len());
                        let mut checked = vec![true; opts.len()];
                        opts.push(opt(format!("CASCADE  (also revoke what {} granted to others)", r.name), CASCADE));
                        checked.push(false);
                        let mut step = multi(title, opts, checked);
                        step.hint = Some("Unchecked ones stay, and DROP ROLE then fails.".into());
                        Next::Ask(step)
                    }
                    1 => {
                        let mut step = input(format!("Type {} to drop it", r.name), false);
                        step.hint = Some("Anything else cancels.".into());
                        Next::Ask(step)
                    }
                    _ => {
                        if one(1) != r.name {
                            return Next::Abort("name did not match; nothing changed".into());
                        }
                        let cascade = if a[0].iter().any(|x| x == CASCADE) { " CASCADE" } else { "" };
                        let mut stages: Vec<(String, Vec<String>)> = Vec::new();
                        for d in a[0].iter().filter_map(|i| deps.get(i.parse::<usize>().ok()?)) {
                            let Some(sql) = revoke_sql(d, &r.ident) else { continue };
                            let db = if d.db.is_empty() { ctx.db } else { &d.db };
                            match stages.iter_mut().find(|(s, _)| s == db) {
                                Some((_, stmts)) => stmts.push(format!("{sql}{cascade}")),
                                None => stages.push((db.to_string(), vec![format!("{sql}{cascade}")])),
                            }
                        }
                        // The connected database runs last, with DROP ROLE.
                        let at = stages.iter().position(|(s, _)| s == ctx.db);
                        let mut last = at.map(|i| stages.remove(i)).unwrap_or_else(|| (ctx.db.to_string(), Vec::new()));
                        last.1.push(format!("DROP ROLE {}", r.ident));
                        stages.sort();
                        stages.push(last);
                        Next::Done(Outcome::Run(drop_stage(&r.name, stages)))
                    }
                }
            }

            Flow::DropStages { role, stages } => Next::Done(Outcome::Run(drop_stage(role, stages.clone()))),

            Flow::CreateDb => match n {
                0 => Next::Ask(input("Name of the new database", false)),
                1 => pick(format!("Owner of {}?", one(0)), role_opts(ctx, false, None)),
                _ => {
                    let name = one(0);
                    if name.is_empty() {
                        return Next::Abort("empty database name".into());
                    }
                    let sql = format!("CREATE DATABASE {} OWNER {}", catalog::quote_ident(&name, ctx.keywords), one(1));
                    let note = "CREATE DATABASE cannot run inside a transaction block; it runs on its own.";
                    let action = Action::new(None, vec![sql], Some(note.into()))
                        .outside_transaction()
                        .followed_by(Flow::DbAccess { name });
                    Next::Done(Outcome::Run(action))
                }
            },

            Flow::DbAccess { name } => {
                let Some(d) = ctx.dbs.iter().find(|d| &d.name == name) else {
                    return Next::Abort(format!("database {name} not found"));
                };
                match n {
                    0 => {
                        let mut opts = vec![opt(
                            "REVOKE CONNECT FROM PUBLIC  (then only the owner, superusers and roles granted CONNECT may connect)",
                            REVOKE_PUBLIC,
                        )];
                        opts.extend(role_opts(ctx, false, None));
                        let checked = vec![false; opts.len()];
                        Next::Ask(
                            multi(format!("{} created. Who may connect? Checked roles get CONNECT.", d.name), opts, checked)
                                .hint("Esc skips: every role keeps CONNECT through PUBLIC."),
                        )
                    }
                    _ => {
                        let (roles, revoke) = split_option(&a[0], REVOKE_PUBLIC);
                        let mut stmts = Vec::new();
                        if revoke {
                            stmts.push(format!("REVOKE CONNECT ON DATABASE {} FROM PUBLIC", d.ident));
                        }
                        if !roles.is_empty() {
                            stmts.push(format!("GRANT CONNECT ON DATABASE {} TO {}", d.ident, roles.join(", ")));
                        }
                        if stmts.is_empty() {
                            return Next::Abort("nothing selected".into());
                        }
                        run(None, stmts, None)
                    }
                }
            }

            Flow::CreateExtension { db } => match n {
                0 => {
                    let opts: Vec<Opt> = ctx
                        .extensions
                        .iter()
                        .filter(|e| e.installed.is_none())
                        .map(|e| opt(format!("{:<20} {:<13} {}", e.name, e.needs(), e.comment), e.name.clone()))
                        .collect();
                    if opts.is_empty() {
                        return Next::Abort("every available extension is installed".into());
                    }
                    pick(format!("CREATE EXTENSION in {db}: which one?"), opts)
                }
                1 => {
                    let mut opts = vec![opt("(default: the schema its control file names, else the first in search_path)", "")];
                    opts.extend(
                        ctx.schemas
                            .iter()
                            .filter(|s| !catalog::system_schema(&s.name))
                            .map(|s| opt(s.name.clone(), s.ident.clone())),
                    );
                    pick(format!("Install {} into which schema?", one(0)), opts)
                }
                _ => {
                    let Some(e) = ctx.extensions.iter().find(|e| e.name == one(0)) else {
                        return Next::Abort(format!("extension {} not found", one(0)));
                    };
                    let mut sql = format!("CREATE EXTENSION {}", catalog::quote_ident(&e.name, ctx.keywords));
                    if !one(1).is_empty() {
                        sql.push_str(&format!(" SCHEMA {}", one(1)));
                    }
                    let mut note = if e.trusted {
                        format!(
                            "Trusted: a role with CREATE on database {db} may install it. Its objects are owned by the \
                             bootstrap superuser."
                        )
                    } else if e.superuser {
                        "Untrusted: only a superuser may install it.".to_string()
                    } else {
                        "Needs the privileges to create its objects.".to_string()
                    };
                    let missing: Vec<&str> = e
                        .requires
                        .iter()
                        .filter(|r| !ctx.extensions.iter().any(|x| &&x.name == r && x.installed.is_some()))
                        .map(String::as_str)
                        .collect();
                    if !missing.is_empty() {
                        sql.push_str(" CASCADE");
                        note.push_str(&format!(" CASCADE also installs {}.", missing.join(", ")));
                    }
                    run(Some(db.clone()), vec![sql], Some(note))
                }
            },

            Flow::Dsn { role, schema } => match n {
                0 => {
                    let opts = ctx.roles.iter().filter(|r| r.login).map(|r| opt(r.name.clone(), r.name.clone())).collect();
                    pick_at("Copy a DSN: connect as which role?", opts, role)
                }
                1 => {
                    let opts = ctx
                        .dbs
                        .iter()
                        .filter(|d| d.allow_conn && !d.template)
                        .map(|d| opt(d.name.clone(), d.name.clone()))
                        .collect();
                    pick_at(format!("{} connects to which database?", one(0)), opts, ctx.db)
                }
                // Schemas are known only for the connected database.
                2 if one(1) != ctx.db => Next::Skip(vec![String::new()]),
                2 => {
                    let mut opts = vec![opt("(none: keep the server's search_path)", "")];
                    opts.extend(
                        ctx.schemas
                            .iter()
                            .filter(|s| !catalog::system_schema(&s.name))
                            .map(|s| opt(s.name.clone(), s.name.clone())),
                    );
                    pick_at("Which schema? search_path becomes that schema, then public.", opts, schema)
                }
                3 => {
                    let path = match one(2).as_str() {
                        "" => None,
                        "public" => Some("public".to_string()),
                        s => Some(format!("{},public", catalog::quote_ident(s, ctx.keywords))),
                    };
                    let opts = [("URL", true), ("keyword", false)]
                        .into_iter()
                        .map(|(kind, url)| {
                            let dsn = ctx.conn.dsn(&one(0), &one(1), path.as_deref(), url);
                            opt(format!("{kind:<8} {dsn}"), dsn)
                        })
                        .collect();
                    pick("Which format? Enter copies it.", opts)
                }
                _ => Next::Done(Outcome::Copy(one(3))),
            },

            Flow::DefGrant { db } => match n {
                0 => pick(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE ?  Rules fire only for objects this role creates.",
                    role_opts(ctx, false, None),
                ),
                1 => pick(
                    "For which kind of object?",
                    catalog::DEFACL_TYPES
                        .iter()
                        .filter(|(code, _)| *code != "L" || ctx.v >= 180000)
                        .map(|(code, kw)| opt(*kw, *code))
                        .collect(),
                ),
                2 if one(1) == "n" => Next::Skip(vec![String::new()]),
                2 => {
                    let mut opts = vec![opt("(all schemas)", "")];
                    opts.extend(
                        ctx.schemas
                            .iter()
                            .filter(|s| !catalog::system_schema(&s.name))
                            .map(|s| opt(s.name.clone(), s.ident.clone())),
                    );
                    pick("In which schema?", opts)
                }
                3 => pick("Grant to which role?", role_opts(ctx, true, None)),
                4 => {
                    let (opts, checked) = priv_opts(&catalog::defacl_privs(&one(1), ctx.v), true);
                    Next::Ask(multi("Which privileges?", opts, checked))
                }
                _ => {
                    let (privs, go) = split_option(&a[4], GRANT_OPTION);
                    if privs.is_empty() {
                        return Next::Abort("no privilege selected".into());
                    }
                    let kw = catalog::defacl_keyword(&one(1));
                    let schema = one(2);
                    let scope = if schema.is_empty() { String::new() } else { format!(" IN SCHEMA {schema}") };
                    let go = if go { " WITH GRANT OPTION" } else { "" };
                    let sql = format!(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {}{scope} GRANT {} ON {kw} TO {}{go}",
                        one(0),
                        privs.join(", "),
                        one(3)
                    );
                    let existing = if matches!(one(1).as_str(), "r" | "S" | "f") {
                        format!("Existing objects need GRANT ... ON ALL {kw} IN SCHEMA.")
                    } else {
                        "Existing objects are unaffected.".to_string()
                    };
                    let note = format!("Applies to {kw} that {} creates from now on. {existing}", one(0));
                    run(Some(db.clone()), vec![sql], Some(note))
                }
            },

            Flow::DefRevoke { db, acl, grant } => match n {
                0 => {
                    let opts: Vec<Opt> = grant.privs.iter().map(|p| opt(p.name.clone(), p.name.clone())).collect();
                    let checked = vec![true; opts.len()];
                    Next::Ask(multi(format!("Stop granting which privileges to {}?", grant.grantee), opts, checked))
                }
                _ => {
                    if a[0].is_empty() {
                        return Next::Abort("no privilege selected".into());
                    }
                    let scope = acl.schema_ident.as_ref().map(|s| format!(" IN SCHEMA {s}")).unwrap_or_default();
                    let sql = format!(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {}{scope} REVOKE {} ON {} FROM {}",
                        acl.creator_ident,
                        a[0].join(", "),
                        catalog::defacl_keyword(&acl.objtype),
                        grant.grantee_ident
                    );
                    run(Some(db.clone()), vec![sql], Some("Existing objects keep their privileges.".into()))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use postgres::Config;

    use super::*;
    use crate::catalog::Priv;

    #[test]
    fn password_is_sent_as_scram_verifier() {
        let lit = scram_literal("it's secret");
        assert!(lit.starts_with("'SCRAM-SHA-256$4096:"), "{lit}");
        assert!(!lit.contains("secret"));
    }

    fn role(oid: u32, name: &str, login: bool) -> Role {
        Role {
            oid,
            name: name.into(),
            ident: name.into(),
            superuser: false,
            inherit: true,
            createrole: false,
            createdb: false,
            login,
            replication: false,
            bypassrls: false,
            connlimit: -1,
            valid_until: None,
            comment: String::new(),
        }
    }

    fn database(name: &str, public_connect: bool) -> Database {
        let privs = if public_connect { vec!["CONNECT", "TEMPORARY"] } else { vec!["TEMPORARY"] };
        Database {
            name: name.into(),
            ident: name.into(),
            owner: "bilal".into(),
            encoding: "UTF8".into(),
            collate: "C".into(),
            ctype: "C".into(),
            allow_conn: true,
            conn_limit: -1,
            template: false,
            size: None,
            acl_default: false,
            comment: String::new(),
            grants: vec![Grant {
                grantee: "PUBLIC".into(),
                grantee_ident: "PUBLIC".into(),
                grantor: "bilal".into(),
                privs: privs.into_iter().map(|p| Priv { name: p.into(), grantable: false }).collect(),
            }],
        }
    }

    fn extension(name: &str, installed: bool, requires: &[&str]) -> Extension {
        Extension {
            name: name.into(),
            installed: installed.then(|| "1.0".into()),
            default_version: Some("1.0".into()),
            schema: None,
            owner: None,
            trusted: true,
            superuser: true,
            relocatable: true,
            requires: requires.iter().map(|r| r.to_string()).collect(),
            comment: String::new(),
        }
    }

    struct Fixture {
        roles: Vec<Role>,
        dbs: Vec<Database>,
        extensions: Vec<Extension>,
        conn: Conn,
        keywords: HashSet<String>,
    }

    impl Fixture {
        fn new() -> Fixture {
            let mut cfg = Config::new();
            cfg.host("/tmp").port(5432);
            Fixture {
                roles: vec![role(1, "agent", true), role(2, "bilal", true), role(3, "struts_app", false)],
                dbs: vec![database("postgres", true), database("struts", false)],
                extensions: vec![extension("cube", false, &[]), extension("earthdistance", false, &["cube"])],
                conn: Conn::new(cfg),
                keywords: HashSet::new(),
            }
        }

        fn ctx(&self, v: i32) -> Ctx<'_> {
            Ctx {
                roles: &self.roles,
                members: &[],
                schemas: &[],
                dbs: &self.dbs,
                extensions: &self.extensions,
                db: "postgres",
                conn: &self.conn,
                v,
                user: "bilal",
                keywords: &self.keywords,
            }
        }
    }

    /// Feeds `answers` to `flow` and returns where it stops.
    fn run(flow: &Flow, ctx: &Ctx, answers: &[&[&str]]) -> Next {
        let mut a: Vec<Vec<String>> = answers.iter().map(|x| x.iter().map(|s| s.to_string()).collect()).collect();
        loop {
            match flow.next(&a, ctx) {
                Next::Skip(x) => a.push(x),
                n => return n,
            }
        }
    }

    fn action(n: Next) -> Action {
        match n {
            Next::Done(Outcome::Run(a)) => a,
            Next::Abort(m) => panic!("aborted: {m}"),
            _ => panic!("flow not done"),
        }
    }

    #[test]
    fn create_role_chains_access() {
        let f = Fixture::new();
        let a = action(run(&Flow::CreateRole, &f.ctx(170000), &[&["app"], &["LOGIN", "INHERIT"], &["pw"]]));
        assert_eq!(a.display, ["CREATE ROLE app WITH LOGIN PASSWORD '********'"]);
        assert!(matches!(a.then.as_deref(), Some(Flow::RoleAccess { name }) if name == "app"));
    }

    #[test]
    fn role_access_grants_connect_and_membership() {
        let f = Fixture::new();
        let flow = Flow::RoleAccess { name: "agent".into() };
        let a = action(run(&flow, &f.ctx(170000), &[&["struts"], &["struts_app"], &["INHERIT", "SET"]]));
        assert_eq!(
            a.exec,
            [
                "GRANT CONNECT ON DATABASE struts TO agent",
                "GRANT struts_app TO agent WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
            ]
        );
        let a = action(run(&flow, &f.ctx(150000), &[&[], &["struts_app"], &[]]));
        assert_eq!(a.exec, ["GRANT struts_app TO agent"]);
        assert!(matches!(run(&flow, &f.ctx(170000), &[&[], &[]]), Next::Abort(_)));
    }

    #[test]
    fn create_db_runs_alone_then_asks_access() {
        let f = Fixture::new();
        let a = action(run(&Flow::CreateDb, &f.ctx(170000), &[&["App"], &["agent"]]));
        assert_eq!(a.exec, [r#"CREATE DATABASE "App" OWNER agent"#]);
        assert!(!a.transaction);
        assert!(matches!(a.then.as_deref(), Some(Flow::DbAccess { name }) if name == "App"));

        let flow = Flow::DbAccess { name: "struts".into() };
        let a = action(run(&flow, &f.ctx(170000), &[&[REVOKE_PUBLIC, "agent"]]));
        assert_eq!(a.exec, ["REVOKE CONNECT ON DATABASE struts FROM PUBLIC", "GRANT CONNECT ON DATABASE struts TO agent"]);
        assert!(a.transaction);
    }

    #[test]
    fn create_extension_cascades_missing_requirements() {
        let f = Fixture::new();
        let flow = Flow::CreateExtension { db: "postgres".into() };
        let a = action(run(&flow, &f.ctx(170000), &[&["earthdistance"], &["app"]]));
        assert_eq!(a.exec, ["CREATE EXTENSION earthdistance SCHEMA app CASCADE"]);
        let a = action(run(&flow, &f.ctx(170000), &[&["cube"], &[""]]));
        assert_eq!(a.exec, ["CREATE EXTENSION cube"]);
    }

    fn dep(db: &str, deptype: &str, kind: &str, ident: &str) -> RoleDep {
        RoleDep {
            db: db.into(),
            deptype: deptype.into(),
            kind: kind.into(),
            ident: ident.into(),
            column: None,
            defacl: None,
            what: format!("{kind} {ident}"),
        }
    }

    #[test]
    fn drop_role_revokes_per_database_then_drops() {
        let f = Fixture::new();
        let mut col = dep("postgres", "a", "table column", "app.t");
        col.column = Some("b".into());
        let mut def = dep("lmsdb", "a", "default acl", "for role bilal in schema app on tables");
        def.defacl = Some(("bilal".into(), Some("app".into()), "r".into()));
        let deps = vec![dep("", "a", "database", "struts"), col, def, dep("lmsdb", "a", "function", "app.f(integer)")];
        let flow = Flow::DropRole { role: role(1, "agent", true), deps };
        let Next::Ask(step) = run(&flow, &f.ctx(170000), &[]) else { panic!("no revoke step") };
        assert_eq!(
            step.opts[2].label,
            "ALTER DEFAULT PRIVILEGES FOR ROLE bilal IN SCHEMA app REVOKE ALL ON TABLES FROM agent  (in lmsdb)"
        );
        assert!(matches!(run(&flow, &f.ctx(170000), &[&["0"], &["agnet"]]), Next::Abort(_)));

        let a = action(run(&flow, &f.ctx(170000), &[&["0", "1", "2", "3", CASCADE], &["agent"]]));
        assert_eq!(a.db.as_deref(), Some("lmsdb"));
        assert_eq!(
            a.exec,
            [
                "ALTER DEFAULT PRIVILEGES FOR ROLE bilal IN SCHEMA app REVOKE ALL ON TABLES FROM agent CASCADE",
                "REVOKE ALL ON FUNCTION app.f(integer) FROM agent CASCADE",
            ]
        );
        let then = a.then.expect("no next stage");
        let a = action(run(&then, &f.ctx(170000), &[]));
        assert_eq!(a.db.as_deref(), Some("postgres"));
        assert_eq!(
            a.exec,
            [
                "REVOKE ALL ON DATABASE struts FROM agent CASCADE",
                "REVOKE ALL (b) ON TABLE app.t FROM agent CASCADE",
                "DROP ROLE agent",
            ]
        );
        assert!(a.then.is_none());
    }

    #[test]
    fn drop_role_stops_on_owned_objects() {
        let f = Fixture::new();
        let deps = vec![dep("", "a", "database", "struts"), dep("lmsdb", "o", "table", "app.t")];
        let flow = Flow::DropRole { role: role(1, "agent", true), deps };
        let Next::Done(Outcome::Blocked { text, .. }) = run(&flow, &f.ctx(170000), &[]) else { panic!("not blocked") };
        assert!(text.starts_with("owner of table app.t  (in lmsdb)\n"), "{text}");
    }

    #[test]
    fn drop_role_without_deps_asks_for_the_name() {
        let f = Fixture::new();
        let flow = Flow::DropRole { role: role(1, "agent", true), deps: Vec::new() };
        let Next::Ask(step) = run(&flow, &f.ctx(170000), &[]) else { panic!("no name step") };
        assert!(matches!(step.kind, StepKind::Input { .. }));
        let a = action(run(&flow, &f.ctx(170000), &[&[], &["agent"]]));
        assert_eq!(a.exec, ["DROP ROLE agent"]);
        assert!(a.note.is_none());
    }

    #[test]
    fn dsn_offers_both_formats() {
        let f = Fixture::new();
        let flow = Flow::Dsn { role: "agent".into(), schema: String::new() };
        let Next::Ask(step) = run(&flow, &f.ctx(170000), &[]) else { panic!("no role step") };
        assert_eq!(step.opts[step.cursor].value, "agent");
        assert!(step.opts.iter().all(|o| o.value != "struts_app"), "NOLOGIN roles cannot connect");

        let Next::Ask(step) = run(&flow, &f.ctx(170000), &[&["agent"], &["postgres"], &["app"]]) else {
            panic!("no format step")
        };
        let dsns: Vec<&str> = step.opts.iter().map(|o| o.value.as_str()).collect();
        assert_eq!(
            dsns,
            [
                "postgresql://agent@/postgres?host=/tmp&port=5432&options=-csearch_path%3Dapp%2Cpublic",
                "host=/tmp port=5432 user=agent dbname=postgres options=-csearch_path=app,public",
            ]
        );
        // No schema step for a database other than the connected one.
        let Next::Ask(step) = run(&flow, &f.ctx(170000), &[&["agent"], &["struts"]]) else { panic!("no format step") };
        assert_eq!(step.opts[0].value, "postgresql://agent@/struts?host=/tmp&port=5432");
    }
}
