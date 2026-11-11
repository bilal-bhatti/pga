//! `?` pane: what the current tab means in PostgreSQL terms, with the MySQL
//! analogue, and the catalog queries behind it.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::app::{App, Tab};
use crate::catalog::*;

fn notes(tab: Tab) -> &'static [&'static str] {
    match tab {
        Tab::Roles => &[
            "PostgreSQL has one kind of principal: the role. A role with LOGIN is what MySQL calls a user; a role \
             without LOGIN acts as a group. Roles belong to the whole server (cluster), not to one database.",
            "MySQL identity includes the client host ('app'@'10.%'). Postgres roles have no host part: pg_hba.conf \
             decides which role may connect from where, to which database, with which auth method.",
            "Attributes (LOGIN, SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS) are flags set with \
             CREATE/ALTER ROLE, not privileges given with GRANT.",
            "GRANT g TO m makes role m a member of role g. With INHERIT, m uses g's privileges automatically; \
             without it, m must run SET ROLE g first. From PG16, INHERIT, SET and ADMIN are stored per membership.",
            "Roles named pg_* are predefined (pg_read_all_data, pg_write_all_data, pg_monitor, pg_signal_backend, \
             ...). Grant them like any role. s shows them.",
            "PUBLIC is a keyword, not a role: a grant to PUBLIC applies to every role, including future ones.",
        ],
        Tab::Databases => &[
            "One server (cluster) holds many databases. A connection is bound to one database and cannot query \
             another; MySQL's db.table across databases has no equivalent. Roles are shared by all databases.",
            "Database privileges: CONNECT (may connect), CREATE (may create schemas), TEMPORARY (may create temp \
             tables). pg_hba.conf must also allow the connection.",
            "New databases give PUBLIC CONNECT and TEMPORARY, so any role can connect until you run \
             REVOKE CONNECT ON DATABASE d FROM PUBLIC.",
            "The owner holds all privileges implicitly; only the owner (or a member of the owning role) and \
             superusers can drop the database. Ownership is not a grant; change it with ALTER DATABASE d OWNER TO r.",
            "Enter switches the current database; tabs 3-6 and 8 read that database's catalog.",
        ],
        Tab::Schemas => &[
            "A schema is a namespace inside one database, the closest thing to a MySQL database. Objects are named \
             schema.object; search_path decides where unqualified names resolve.",
            "USAGE lets a role look up objects in the schema; CREATE lets it create objects there. Without USAGE, \
             every grant on the tables inside is unusable.",
            "From PG15, schema public is owned by pg_database_owner and PUBLIC no longer has CREATE on it.",
            "pg_catalog and information_schema hold the system catalogs; s shows them.",
        ],
        Tab::Objects => &[
            "Tables, views and foreign tables: SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, \
             and MAINTAIN from PG17. Sequences: USAGE, SELECT, UPDATE. Functions and procedures: EXECUTE.",
            "The owner (normally the creator) holds every privilege implicitly. Only the owner, a member of the \
             owning role, or a superuser can ALTER or DROP the object.",
            "New functions are executable by PUBLIC by default; new tables give nothing to anyone but the owner.",
            "GRANT ... ON ALL TABLES IN SCHEMA s covers existing tables only. Future tables need default \
             privileges (tab 5).",
            "A grant here counts only with CONNECT on the database and USAGE on the schema. Tab 8 checks every layer.",
            "* marks WITH GRANT OPTION: the grantee may grant the privilege to others.",
        ],
        Tab::Defaults => &[
            "ALTER DEFAULT PRIVILEGES stores grants added automatically to objects created later. In MySQL a \
             schema-level grant covers future tables; in Postgres object grants never do.",
            "A rule belongs to the creating role (FOR ROLE) and fires only when that role creates the object. \
             Objects created by another role, e.g. a migration user, get nothing from it.",
            "Rules IN SCHEMA s add to the defaults. Rules without a schema replace the built-in defaults for that \
             object type, e.g. REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC.",
            "Existing objects are unaffected; use GRANT ... ON ALL TABLES IN SCHEMA s for those.",
        ],
        Tab::Rls => &[
            "Row-level security filters rows per role. MySQL has no built-in equivalent.",
            "ALTER TABLE t ENABLE ROW LEVEL SECURITY turns it on. With RLS on and no policies, every role subject \
             to RLS sees no rows (default deny).",
            "PERMISSIVE policies are combined with OR; RESTRICTIVE policies are AND-ed on top. USING filters rows \
             that are read, updated or deleted; WITH CHECK validates rows that are written.",
            "The owner bypasses RLS unless FORCE ROW LEVEL SECURITY is set. Superusers and BYPASSRLS roles always \
             bypass it.",
            "RLS applies after table privileges: a role still needs SELECT etc. on the table.",
        ],
        Tab::Settings => &[
            "ALTER ROLE r SET p = v, ALTER DATABASE d SET p = v and ALTER ROLE r IN DATABASE d SET p = v store \
             session defaults (search_path, statement_timeout, ...). They apply when a session starts.",
            "Precedence: role in database, then role, then database, then postgresql.conf. A session can still \
             override with SET.",
        ],
        Tab::Access => &[
            "Effective privileges of one role in the current database, after role membership, PUBLIC grants, \
             ownership and superuser status, as computed by has_*_privilege() and pg_has_role().",
            "Layers: CONNECT on the database, then USAGE on the schema, then the object privilege. Dim rows are \
             blocked by a missing layer above them, or have no privileges.",
            "Via lists the grants that apply to the role: direct, through a role it inherits from, or PUBLIC. \
             Roles listed as 'only after SET ROLE' contribute nothing until the session switches to them.",
            "Tables with RLS may still filter rows; the detail pane says whether they do for this role.",
        ],
    }
}

fn queries(tab: Tab, v: i32) -> Vec<String> {
    match tab {
        Tab::Roles => vec![ROLES_SQL.into(), members_sql(v).into()],
        Tab::Databases => vec![DATABASES_SQL.into(), database_acl_sql()],
        Tab::Schemas => vec![SCHEMAS_SQL.into(), schema_acl_sql()],
        Tab::Objects => vec![relations_sql(), relation_acl_sql(), column_acl_sql(), routines_sql(), routine_acl_sql()],
        Tab::Defaults => vec![DEFACL_SQL.into(), defacl_acl_sql()],
        Tab::Rls => vec![RLS_SQL.into(), POLICIES_SQL.into()],
        Tab::Settings => vec![SETTINGS_SQL.into()],
        Tab::Access => vec![reach_sql(v).into(), access_sql(v)],
    }
}

pub fn lines(app: &App) -> Vec<Line<'static>> {
    let head = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let mut out = Vec::new();
    for n in notes(app.tab) {
        out.push(Line::from(format!("• {n}")));
        out.push(Line::default());
    }
    let title = if app.tab == Tab::Access { "SQL ($1 = role oid)" } else { "SQL" };
    out.push(Line::from(Span::styled(title, head)));
    for q in queries(app.tab, app.server.version_num) {
        out.push(Line::default());
        for l in q.lines() {
            out.push(Line::from(Span::styled(l.to_string(), Style::new().fg(Color::Cyan))));
        }
    }
    out
}
