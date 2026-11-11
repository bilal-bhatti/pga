//! Right-hand pane: everything known about the selected row.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::app::{App, Tab};
use crate::catalog::{self, Grant};

type Lines = Vec<Line<'static>>;

fn head(out: &mut Lines, s: impl Into<String>) {
    if !out.is_empty() {
        out.push(Line::default());
    }
    out.push(Line::from(Span::styled(s.into(), Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD))));
}

fn kv(out: &mut Lines, k: &str, v: impl Into<String>) {
    out.push(Line::from(vec![Span::styled(format!("  {k:<17} "), Style::new().fg(Color::DarkGray)), Span::raw(v.into())]));
}

fn item(out: &mut Lines, s: impl Into<String>) {
    out.push(Line::from(format!("  {}", s.into())));
}

fn note(out: &mut Lines, s: impl Into<String>) {
    out.push(Line::from(Span::styled(format!("  {}", s.into()), Style::new().fg(Color::DarkGray).italic())));
}

fn yes(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn grants(out: &mut Lines, grants: &[Grant], acl_default: bool) {
    head(out, "Privileges");
    if acl_default {
        note(out, "no GRANT/REVOKE yet: these are the built-in defaults");
    }
    if grants.is_empty() {
        note(out, "none: only the owner and superusers have access");
    }
    let w = grants.iter().map(|g| g.grantee.len()).max().unwrap_or(0);
    for g in grants {
        out.push(Line::from(vec![
            Span::styled(format!("  {:<w$}  ", g.grantee), Style::new().fg(Color::Cyan)),
            Span::raw(g.privs_text()),
            Span::styled(format!("  by {}", g.grantor), Style::new().fg(Color::DarkGray)),
        ]));
    }
    if grants.iter().any(|g| g.privs.iter().any(|p| p.grantable)) {
        note(out, "* = WITH GRANT OPTION");
    }
}

pub fn lines(app: &App) -> Lines {
    let mut out = Vec::new();
    let sel = app.selected();
    match (app.tab(), sel) {
        (Tab::Access, _) => access(app, sel, &mut out),
        (_, None) => note(&mut out, "nothing selected"),
        (Tab::Roles, Some((i, _))) => role(app, i, &mut out),
        (Tab::Databases, Some((i, _))) => database(app, i, &mut out),
        (Tab::Memberships, Some((i, _))) => membership(app, i, &mut out),
        (Tab::Schemas, Some((i, _))) => schema(app, i, &mut out),
        (Tab::Objects, Some((i, _))) => object(app, i, &mut out),
        (Tab::Defaults, Some((i, j))) => default_acl(app, i, j, &mut out),
        (Tab::Rls, Some((i, _))) => rls(app, i, &mut out),
        (Tab::Settings, Some((i, _))) => setting(app, i, &mut out),
    }
    out
}

fn membership(app: &App, i: usize, out: &mut Lines) {
    let m = &app.shared.members[i];
    let (group, member) = (app.role_name(m.role), app.role_name(m.member));
    head(out, format!("{member} is a member of {group}"));
    kv(out, "INHERIT", format!("{:<4} {member} uses the privileges of {group} without SET ROLE", yes(m.inherit)));
    kv(out, "SET", format!("{:<4} {member} may SET ROLE {group}", yes(m.set)));
    kv(out, "ADMIN", format!("{:<4} {member} may grant {group} to other roles and revoke it", yes(m.admin)));
    kv(out, "granted by", m.grantor.clone());
}

fn role(app: &App, i: usize, out: &mut Lines) {
    let r = &app.shared.roles[i];
    head(out, format!("Role {}", r.name));
    if !r.comment.is_empty() {
        note(out, r.comment.clone());
    }
    if r.system() {
        note(out, "predefined role: grant it to give its built-in capability");
    }
    head(out, "Attributes");
    kv(out, "LOGIN", format!("{:<4} may connect", yes(r.login)));
    kv(out, "SUPERUSER", format!("{:<4} bypasses every permission check", yes(r.superuser)));
    let inherit = if app.server.version_num >= 160000 {
        "default INHERIT for new memberships"
    } else {
        "uses privileges of its roles without SET ROLE"
    };
    kv(out, "INHERIT", format!("{:<4} {inherit}", yes(r.inherit)));
    kv(out, "CREATEDB", format!("{:<4} may create databases", yes(r.createdb)));
    kv(out, "CREATEROLE", format!("{:<4} may create and alter roles", yes(r.createrole)));
    kv(out, "REPLICATION", format!("{:<4} may stream replication", yes(r.replication)));
    kv(out, "BYPASSRLS", format!("{:<4} ignores row-level security", yes(r.bypassrls)));
    kv(out, "connection limit", if r.connlimit < 0 { "none".into() } else { r.connlimit.to_string() });
    kv(out, "password expires", r.valid_until.clone().unwrap_or_else(|| "never".into()));

    let membership = |m: &catalog::Member| format!("inherit={} set={} admin={}  by {}", yes(m.inherit), yes(m.set), yes(m.admin), m.grantor);
    head(out, "Member of (gets privileges from)");
    let mut any = false;
    for m in app.shared.members.iter().filter(|m| m.member == r.oid) {
        item(out, format!("{:<20} {}", app.role_name(m.role), membership(m)));
        any = true;
    }
    if !any {
        note(out, "none");
    }
    head(out, format!("Members (get privileges of {})", r.name));
    any = false;
    for m in app.shared.members.iter().filter(|m| m.role == r.oid) {
        item(out, format!("{:<20} {}", app.role_name(m.member), membership(m)));
        any = true;
    }
    if !any {
        note(out, "none");
    }

    let owned: Vec<&str> = app.shared.dbs.iter().filter(|d| d.owner == r.name).map(|d| d.name.as_str()).collect();
    if !owned.is_empty() {
        head(out, "Owns databases");
        item(out, owned.join(", "));
    }
    let settings: Vec<_> = app.shared.settings.iter().filter(|s| s.role == r.name).collect();
    if !settings.is_empty() {
        head(out, "Settings");
        for s in settings {
            let scope = if s.db.is_empty() { "all databases".to_string() } else { format!("in {}", s.db) };
            item(out, format!("{}  ({scope})", s.setting));
        }
    }
    head(out, "Keys");
    note(out, "Enter opens the role: its access in the current database, memberships and settings");
}

fn database(app: &App, i: usize, out: &mut Lines) {
    let d = &app.shared.dbs[i];
    head(out, format!("Database {}", d.name));
    if !d.comment.is_empty() {
        note(out, d.comment.clone());
    }
    if d.name == app.db {
        note(out, "connected (●)");
    }
    kv(out, "owner", d.owner.clone());
    kv(out, "encoding", d.encoding.clone());
    kv(out, "collate / ctype", format!("{} / {}", d.collate, d.ctype));
    kv(out, "size", d.size.clone().unwrap_or_else(|| "(no CONNECT privilege)".into()));
    kv(out, "allow connections", yes(d.allow_conn));
    kv(out, "connection limit", if d.conn_limit < 0 { "none".into() } else { d.conn_limit.to_string() });
    kv(out, "template", yes(d.template));
    grants(out, &d.grants, d.acl_default);
    let settings: Vec<_> = app.shared.settings.iter().filter(|s| s.db == d.name).collect();
    if !settings.is_empty() {
        head(out, "Settings");
        for s in settings {
            let scope = if s.role.is_empty() { "all roles".to_string() } else { format!("role {}", s.role) };
            item(out, format!("{}  ({scope})", s.setting));
        }
    }
    head(out, "Keys");
    note(out, "Enter opens the database: schemas, objects, default privileges, RLS");
}

fn schema(app: &App, i: usize, out: &mut Lines) {
    let s = &app.local.schemas[i];
    head(out, format!("Schema {}.{}", app.db, s.name));
    if !s.comment.is_empty() {
        note(out, s.comment.clone());
    }
    kv(out, "owner", s.owner.clone());
    kv(out, "relations", s.relations.to_string());
    kv(out, "routines", s.routines.to_string());
    grants(out, &s.grants, s.acl_default);
    let rules: Vec<_> = app.local.defacls.iter().filter(|d| d.schema.as_deref() == Some(s.name.as_str())).collect();
    if !rules.is_empty() {
        head(out, "Default privileges for new objects here");
        for d in rules {
            for g in &d.grants {
                item(
                    out,
                    format!("{} created by {} → {}: {}", catalog::defacl_keyword(&d.objtype), d.creator, g.grantee, g.privs_text()),
                );
            }
        }
    }
}

fn object(app: &App, i: usize, out: &mut Lines) {
    let o = &app.local.objects[i];
    head(out, format!("{} {}.{}", o.kind.label(), o.schema, o.name));
    kv(out, "owner", o.owner.clone());
    if o.kind.has_rls() {
        let state = match (o.rls, o.force_rls) {
            (true, true) => "enabled and forced (applies to the owner too)",
            (true, false) => "enabled (owner bypasses)",
            _ => "disabled",
        };
        kv(out, "row-level security", state);
        kv(out, "policies", o.policies.to_string());
    }
    grants(out, &o.grants, o.acl_default);
    if !o.columns.is_empty() {
        head(out, "Column privileges");
        for (col, gs) in &o.columns {
            for g in gs {
                item(out, format!("{col}: {} {}  by {}", g.grantee, g.privs_text(), g.grantor));
            }
        }
    }
}

fn default_acl(app: &App, i: usize, j: usize, out: &mut Lines) {
    let d = &app.local.defacls[i];
    let g = &d.grants[j];
    let kw = catalog::defacl_keyword(&d.objtype);
    head(out, "Default privilege rule");
    kv(out, "objects created by", d.creator.clone());
    kv(out, "in schema", d.schema.clone().unwrap_or_else(|| "(any)".into()));
    kv(out, "object type", kw);
    kv(out, "grantee", g.grantee.clone());
    kv(out, "privileges", g.privs_text());
    head(out, "Effect");
    let place = d.schema.as_ref().map(|s| format!("in schema {s}")).unwrap_or_else(|| "in any schema".into());
    item(out, format!("When {} creates {kw} {place},", d.creator));
    item(out, format!("{} gets {} on them automatically.", g.grantee, g.privs_text()));
    note(out, "Objects created by other roles are not affected; neither are existing objects.");
    if d.schema.is_none() {
        note(out, "No schema: this rule replaces the built-in defaults for this object type.");
    }
    if d.grants.len() > 1 {
        head(out, "All grants in this rule");
        for g in &d.grants {
            item(out, format!("{}: {}", g.grantee, g.privs_text()));
        }
    }
}

fn rls(app: &App, i: usize, out: &mut Lines) {
    let t = &app.local.rls[i];
    head(out, format!("Table {}.{}", t.schema, t.name));
    kv(out, "owner", t.owner.clone());
    kv(out, "RLS enabled", yes(t.enabled));
    kv(out, "RLS forced", yes(t.forced));
    head(out, "Effect");
    match (t.enabled, t.policies.is_empty()) {
        (false, _) => note(out, "RLS is off: the policies below have no effect."),
        (true, true) => note(out, "No policies: default deny, other roles see no rows."),
        (true, false) => note(out, "Rows are filtered by the policies below."),
    }
    if t.enabled {
        let owner = if t.forced { "The owner is filtered too (FORCE)." } else { "The owner is not filtered." };
        note(out, format!("{owner} Superusers and BYPASSRLS roles are never filtered."));
    }
    for p in &t.policies {
        head(out, format!("Policy {}", p.name));
        kv(out, "type", if p.permissive { "PERMISSIVE (OR with other permissive)" } else { "RESTRICTIVE (AND)" });
        kv(out, "command", p.cmd.clone());
        kv(out, "roles", p.roles.join(", "));
        if !p.using.is_empty() {
            kv(out, "USING", p.using.clone());
        }
        if !p.check.is_empty() {
            kv(out, "WITH CHECK", p.check.clone());
        }
    }
}

fn setting(app: &App, i: usize, out: &mut Lines) {
    let s = &app.shared.settings[i];
    head(out, "Stored setting");
    kv(out, "setting", s.setting.clone());
    kv(out, "role", if s.role.is_empty() { "(all roles)".into() } else { s.role.clone() });
    kv(out, "database", if s.db.is_empty() { "(all databases)".into() } else { s.db.clone() });
    let sql = match (s.role.is_empty(), s.db.is_empty()) {
        (false, false) => format!("ALTER ROLE {} IN DATABASE {} SET ...", s.role, s.db),
        (false, true) => format!("ALTER ROLE {} SET ...", s.role),
        (true, false) => format!("ALTER DATABASE {} SET ...", s.db),
        (true, true) => "ALTER ROLE ALL SET ...".into(),
    };
    kv(out, "set by", sql);
}

fn access(app: &App, sel: Option<(usize, usize)>, out: &mut Lines) {
    let Some(a) = &app.access else {
        note(out, "Access not loaded. ^r retries.");
        return;
    };
    let r = &a.role;
    head(out, format!("Role {} in database {}", r.name, a.db));
    if r.superuser {
        note(out, "SUPERUSER: every permission check passes.");
    }
    if r.bypassrls {
        note(out, "BYPASSRLS: row-level security never filters this role.");
    }
    if !r.login {
        note(out, "NOLOGIN: cannot connect itself; reached by members through inheritance or SET ROLE.");
    }
    match sel {
        Some((0, i)) => {
            let reach = &a.reach[i];
            head(out, format!("Role {}", reach.name));
            if reach.usage {
                item(out, format!("{} uses the privileges of {} directly.", r.name, reach.name));
            } else {
                item(out, format!("{} gets no privileges from {} until it runs:", r.name, reach.name));
                item(out, format!("SET ROLE {};", reach.name));
            }
            kv(out, "SET ROLE allowed", yes(reach.set));
        }
        Some((_, i)) => {
            let it = &a.items[i];
            let name = match &it.schema {
                Some(s) if it.kind != "schema" => format!("{s}.{}", it.name),
                _ => it.name.clone(),
            };
            head(out, format!("{} {}", it.kind, name));
            kv(out, "privileges", if it.privs.is_empty() { "none".into() } else { it.privs.join(", ") });
            if !it.column_privs.is_empty() {
                kv(out, "on some columns", it.column_privs.join(", "));
            }
            kv(out, "owner (or member)", yes(it.owner));
            if let Some(b) = &it.blocked {
                kv(out, "usable", format!("no: {b}"));
            }
            if it.rls {
                let filtered = !r.superuser && !r.bypassrls && (!it.owner || it.forced);
                kv(out, "row-level security", if filtered { "on: rows filtered by policies" } else { "on, but bypassed" });
            }
            head(out, "Grants that apply");
            if it.via.is_empty() {
                note(out, "none");
            }
            for v in it.via.split("; ").filter(|v| !v.is_empty()) {
                item(out, v.to_string());
            }
            note(out, "Direct grants, grants to inherited roles, and PUBLIC.");
        }
        None => {}
    }
}
