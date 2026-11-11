//! Multi-step flows that end in SQL to confirm, or in a navigation outcome.
//! Each flow asks one step at a time; answers are collected in order.

use std::collections::HashSet;

use crate::catalog::{self, Database, DefAcl, Grant, Member, Role, Schema};

pub struct Ctx<'a> {
    pub roles: &'a [Role],
    pub members: &'a [Member],
    pub schemas: &'a [Schema],
    pub dbs: &'a [Database],
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
}

impl Action {
    fn new(db: Option<String>, stmts: Vec<String>, note: Option<String>) -> Action {
        Action { db, display: stmts.clone(), exec: stmts, note }
    }
}

pub enum Outcome {
    Run(Action),
    UseDb(String),
    Inspect(u32),
}

pub enum Flow {
    UseDb,
    Inspect,
    Grant(Target),
    Revoke(Target),
    Owner(Target),
    CreateRole,
    EditRole(Role),
    Password(Role),
    Join(Role),
    Leave(Role),
    DropRole(Role),
    DefGrant { db: String },
    DefRevoke { db: String, acl: DefAcl, grant: Grant },
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

            Flow::Inspect => match n {
                0 => {
                    let mut roles: Vec<&Role> = ctx.roles.iter().collect();
                    roles.sort_by_key(|r| (r.system(), r.name.clone()));
                    pick(
                        "Show effective access of which role?",
                        roles.into_iter().map(|r| opt(role_label(r), r.oid.to_string())).collect(),
                    )
                }
                _ => Next::Done(Outcome::Inspect(one(0).parse().unwrap_or_default())),
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
                    if password.is_empty() {
                        return run(None, vec![sql], None);
                    }
                    let sep = if words.is_empty() { " WITH" } else { "" };
                    Next::Done(Outcome::Run(Action {
                        db: None,
                        display: vec![format!("{sql}{sep} PASSWORD '********'")],
                        exec: vec![format!("{sql}{sep} PASSWORD {}", scram_literal(&password))],
                        note: None,
                    }))
                }
            },

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
                    Next::Done(Outcome::Run(Action {
                        db: None,
                        display: vec![format!("ALTER ROLE {} PASSWORD '********'", r.ident)],
                        exec: vec![format!("ALTER ROLE {} PASSWORD {}", r.ident, scram_literal(&pw))],
                        note: None,
                    }))
                }
            },

            Flow::Join(r) => match n {
                0 => pick(format!("Make {} a member of which role?", r.name), role_opts(ctx, false, Some(r.oid))),
                1 if ctx.v >= 160000 => Next::Ask(multi(
                    format!("GRANT {} TO {}: membership options", one(0), r.name),
                    vec![
                        opt("ADMIN    may grant this membership to others", "ADMIN"),
                        opt("INHERIT  uses the role's privileges without SET ROLE", "INHERIT"),
                        opt("SET      may SET ROLE to the role", "SET"),
                    ],
                    vec![false, r.inherit, true],
                )),
                1 => Next::Ask(multi(
                    format!("GRANT {} TO {}: options", one(0), r.name),
                    vec![opt("WITH ADMIN OPTION  may grant this membership to others", "ADMIN")],
                    vec![false],
                )),
                _ => {
                    let on = |k: &str| if a[1].iter().any(|x| x == k) { "TRUE" } else { "FALSE" };
                    let sql = if ctx.v >= 160000 {
                        format!("GRANT {} TO {} WITH ADMIN {}, INHERIT {}, SET {}", one(0), r.ident, on("ADMIN"), on("INHERIT"), on("SET"))
                    } else if on("ADMIN") == "TRUE" {
                        format!("GRANT {} TO {} WITH ADMIN OPTION", one(0), r.ident)
                    } else {
                        format!("GRANT {} TO {}", one(0), r.ident)
                    };
                    run(None, vec![sql], None)
                }
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

            Flow::DropRole(r) => run(
                None,
                vec![format!("DROP ROLE {}", r.ident)],
                Some(format!(
                    "Fails while {0} owns objects or holds privileges in any database. Clear those first, in each \
                     database: REASSIGN OWNED BY {0} TO <other role>; DROP OWNED BY {0};",
                    r.ident
                )),
            ),

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
    use super::scram_literal;

    #[test]
    fn password_is_sent_as_scram_verifier() {
        let lit = scram_literal("it's secret");
        assert!(lit.starts_with("'SCRAM-SHA-256$4096:"), "{lit}");
        assert!(!lit.contains("secret"));
    }
}
