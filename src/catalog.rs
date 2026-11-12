use std::collections::{HashMap, HashSet};

use anyhow::Result;
use postgres::{Client, Row};

/// Grantee 0 in an ACL is PUBLIC.
pub const GRANTEE: &str = "case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee)::text end";
const GRANTEE_IDENT: &str = "case when a.grantee = 0 then 'PUBLIC' else quote_ident(pg_get_userbyid(a.grantee)) end";

pub const DATABASE_PRIVS: &[&str] = &["CONNECT", "CREATE", "TEMPORARY"];
pub const SCHEMA_PRIVS: &[&str] = &["USAGE", "CREATE"];
pub const SEQUENCE_PRIVS: &[&str] = &["USAGE", "SELECT", "UPDATE"];
pub const ROUTINE_PRIVS: &[&str] = &["EXECUTE"];
const TABLE_PRIVS: &[&str] = &["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"];

/// MAINTAIN exists from PostgreSQL 17.
pub fn table_privs(v: i32) -> Vec<&'static str> {
    let mut p = TABLE_PRIVS.to_vec();
    if v >= 170000 {
        p.push("MAINTAIN");
    }
    p
}

pub fn system_schema(name: &str) -> bool {
    name.starts_with("pg_") || name == "information_schema"
}

/// One row per (key, grantee, grantor, privilege). `acl` is NULL until the
/// first GRANT/REVOKE, meaning the built-in defaults, so callers pass
/// `coalesce(acl, acldefault(..))`.
pub fn acl_sql(key: &str, from: &str, acl: &str) -> String {
    format!(
        "select {key}, {GRANTEE}, {GRANTEE_IDENT}, pg_get_userbyid(a.grantor)::text,\n       \
         a.privilege_type, a.is_grantable\n\
         from {from}, aclexplode({acl}) a\n\
         order by 1, a.grantee, a.grantor"
    )
}

pub fn quote_ident(s: &str, keywords: &HashSet<String>) -> String {
    let plain = s.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !keywords.contains(s);
    if plain { s.to_string() } else { format!("\"{}\"", s.replace('"', "\"\"")) }
}

#[derive(Clone, Debug)]
pub struct Priv {
    pub name: String,
    pub grantable: bool,
}

#[derive(Clone, Debug)]
pub struct Grant {
    pub grantee: String,
    pub grantee_ident: String,
    pub grantor: String,
    pub privs: Vec<Priv>,
}

impl Grant {
    /// `*` marks WITH GRANT OPTION.
    pub fn privs_text(&self) -> String {
        let names: Vec<String> =
            self.privs.iter().map(|p| if p.grantable { format!("{}*", p.name) } else { p.name.clone() }).collect();
        names.join(", ")
    }
}

pub fn grantees(grants: &[Grant]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for g in grants {
        if !names.contains(&g.grantee.as_str()) {
            names.push(&g.grantee);
        }
    }
    names.join(", ")
}

/// Reads grantee, grantee ident, grantor, privilege, grantable from `at`.
fn add_grant(list: &mut Vec<Grant>, row: &Row, at: usize) {
    let grantee: String = row.get(at);
    let grantor: String = row.get(at + 2);
    let p = Priv { name: row.get(at + 3), grantable: row.get(at + 4) };
    match list.iter_mut().find(|g| g.grantee == grantee && g.grantor == grantor) {
        Some(g) => g.privs.push(p),
        None => list.push(Grant { grantee, grantee_ident: row.get(at + 1), grantor, privs: vec![p] }),
    }
}

fn acl_map(c: &mut Client, sql: &str) -> Result<HashMap<u32, Vec<Grant>>> {
    let mut map: HashMap<u32, Vec<Grant>> = HashMap::new();
    for row in c.query(sql, &[])? {
        add_grant(map.entry(row.get(0)).or_default(), &row, 1);
    }
    Ok(map)
}

pub struct Server {
    pub version_num: i32,
    pub version: String,
    pub user: String,
    pub superuser: bool,
    /// Keywords that need quoting as identifiers, as in the server's quote_ident().
    pub keywords: HashSet<String>,
}

pub fn server(c: &mut Client) -> Result<Server> {
    let r = c.query_one(
        "select current_setting('server_version_num')::int, current_setting('server_version'), current_user::text,
                (select rolsuper from pg_roles where rolname = current_user)",
        &[],
    )?;
    let keywords = c
        .query("select word from pg_get_keywords() where catcode <> 'U'", &[])?
        .iter()
        .map(|r| r.get(0))
        .collect();
    Ok(Server { version_num: r.get(0), version: r.get(1), user: r.get(2), superuser: r.get(3), keywords })
}

// ---- shared catalogs: visible from every database ----

#[derive(Clone, Debug)]
pub struct Role {
    pub oid: u32,
    pub name: String,
    pub ident: String,
    pub superuser: bool,
    pub inherit: bool,
    pub createrole: bool,
    pub createdb: bool,
    pub login: bool,
    pub replication: bool,
    pub bypassrls: bool,
    pub connlimit: i32,
    pub valid_until: Option<String>,
    pub comment: String,
}

impl Role {
    pub fn system(&self) -> bool {
        self.name.starts_with("pg_")
    }

    /// Attributes that differ from CREATE ROLE defaults.
    pub fn attributes(&self) -> Vec<&'static str> {
        let mut a = Vec::new();
        for (on, name) in [
            (self.superuser, "superuser"),
            (self.createrole, "createrole"),
            (self.createdb, "createdb"),
            (self.replication, "replication"),
            (self.bypassrls, "bypassrls"),
            (!self.inherit, "noinherit"),
        ] {
            if on {
                a.push(name);
            }
        }
        a
    }
}

pub const ROLES_SQL: &str = "\
select r.oid, r.rolname::text, quote_ident(r.rolname), r.rolsuper, r.rolinherit,
       r.rolcreaterole, r.rolcreatedb, r.rolcanlogin, r.rolreplication, r.rolbypassrls,
       r.rolconnlimit, r.rolvaliduntil::text, coalesce(shobj_description(r.oid, 'pg_authid'), '')
from pg_roles r
order by r.rolname";

/// A row of pg_auth_members: `member` belongs to `role`.
#[derive(Clone, Debug)]
pub struct Member {
    pub role: u32,
    pub member: u32,
    pub grantor: String,
    pub grantor_ident: String,
    pub admin: bool,
    pub inherit: bool,
    pub set: bool,
}

/// Before PostgreSQL 16, INHERIT came from the member role and SET was implied.
pub fn members_sql(v: i32) -> &'static str {
    if v >= 160000 {
        "\
select m.roleid, m.member, pg_get_userbyid(m.grantor)::text, quote_ident(pg_get_userbyid(m.grantor)),
       m.admin_option, m.inherit_option, m.set_option
from pg_auth_members m"
    } else {
        "\
select m.roleid, m.member, pg_get_userbyid(m.grantor)::text, quote_ident(pg_get_userbyid(m.grantor)),
       m.admin_option, r.rolinherit, true
from pg_auth_members m join pg_roles r on r.oid = m.member"
    }
}

#[derive(Clone, Debug)]
pub struct Database {
    pub name: String,
    pub ident: String,
    pub owner: String,
    pub encoding: String,
    pub collate: String,
    pub ctype: String,
    pub allow_conn: bool,
    pub conn_limit: i32,
    pub template: bool,
    pub size: Option<String>,
    pub acl_default: bool,
    pub comment: String,
    pub grants: Vec<Grant>,
}

pub const DATABASES_SQL: &str = "\
select d.oid, d.datname::text, quote_ident(d.datname), pg_get_userbyid(d.datdba)::text,
       pg_encoding_to_char(d.encoding)::text, d.datcollate::text, d.datctype::text,
       d.datallowconn, d.datconnlimit, d.datistemplate,
       case when has_database_privilege(d.oid, 'CONNECT') then pg_size_pretty(pg_database_size(d.oid)) end,
       d.datacl is null, coalesce(shobj_description(d.oid, 'pg_database'), '')
from pg_database d
order by d.datname";

pub fn database_acl_sql() -> String {
    acl_sql("d.oid", "pg_database d", "coalesce(d.datacl, acldefault('d', d.datdba))")
}

/// A stored session default from ALTER ROLE / ALTER DATABASE ... SET.
#[derive(Clone, Debug)]
pub struct Setting {
    /// Empty means every role.
    pub role: String,
    /// Empty means every database.
    pub db: String,
    pub setting: String,
}

pub const SETTINGS_SQL: &str = "\
select coalesce(r.rolname::text, ''), coalesce(d.datname::text, ''), c
from pg_db_role_setting s
left join pg_roles r on r.oid = s.setrole
left join pg_database d on d.oid = s.setdatabase,
unnest(s.setconfig) c
order by 1, 2, 3";

#[derive(Default)]
pub struct Shared {
    pub roles: Vec<Role>,
    pub members: Vec<Member>,
    pub dbs: Vec<Database>,
    pub settings: Vec<Setting>,
}

pub fn load_shared(c: &mut Client, v: i32) -> Result<Shared> {
    let roles = c
        .query(ROLES_SQL, &[])?
        .iter()
        .map(|r| Role {
            oid: r.get(0),
            name: r.get(1),
            ident: r.get(2),
            superuser: r.get(3),
            inherit: r.get(4),
            createrole: r.get(5),
            createdb: r.get(6),
            login: r.get(7),
            replication: r.get(8),
            bypassrls: r.get(9),
            connlimit: r.get(10),
            valid_until: r.get(11),
            comment: r.get(12),
        })
        .collect();
    let members = c
        .query(members_sql(v), &[])?
        .iter()
        .map(|r| Member {
            role: r.get(0),
            member: r.get(1),
            grantor: r.get(2),
            grantor_ident: r.get(3),
            admin: r.get(4),
            inherit: r.get(5),
            set: r.get(6),
        })
        .collect();
    let mut acl = acl_map(c, &database_acl_sql())?;
    let dbs = c
        .query(DATABASES_SQL, &[])?
        .iter()
        .map(|r| Database {
            name: r.get(1),
            ident: r.get(2),
            owner: r.get(3),
            encoding: r.get(4),
            collate: r.get(5),
            ctype: r.get(6),
            allow_conn: r.get(7),
            conn_limit: r.get(8),
            template: r.get(9),
            size: r.get(10),
            acl_default: r.get(11),
            comment: r.get(12),
            grants: acl.remove(&r.get(0)).unwrap_or_default(),
        })
        .collect();
    let settings = c
        .query(SETTINGS_SQL, &[])?
        .iter()
        .map(|r| Setting { role: r.get(0), db: r.get(1), setting: r.get(2) })
        .collect();
    Ok(Shared { roles, members, dbs, settings })
}

// ---- per-database catalogs ----

#[derive(Clone, Debug)]
pub struct Schema {
    pub name: String,
    pub ident: String,
    pub owner: String,
    pub acl_default: bool,
    pub relations: i64,
    pub routines: i64,
    pub comment: String,
    pub grants: Vec<Grant>,
}

pub const SCHEMAS_SQL: &str = "\
select n.oid, n.nspname::text, quote_ident(n.nspname), pg_get_userbyid(n.nspowner)::text, n.nspacl is null,
       (select count(*) from pg_class c where c.relnamespace = n.oid and c.relkind in ('r','p','v','m','S','f')),
       (select count(*) from pg_proc p where p.pronamespace = n.oid),
       coalesce(obj_description(n.oid, 'pg_namespace'), '')
from pg_namespace n
order by n.nspname";

pub fn schema_acl_sql() -> String {
    acl_sql("n.oid", "pg_namespace n", "coalesce(n.nspacl, acldefault('n', n.nspowner))")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Table,
    PartTable,
    View,
    MatView,
    Sequence,
    Foreign,
    Function,
    Procedure,
    Aggregate,
    Window,
}

impl Kind {
    fn parse(s: &str) -> Kind {
        match s {
            "partitioned table" => Kind::PartTable,
            "view" => Kind::View,
            "materialized view" => Kind::MatView,
            "sequence" => Kind::Sequence,
            "foreign table" => Kind::Foreign,
            "function" => Kind::Function,
            "procedure" => Kind::Procedure,
            "aggregate" => Kind::Aggregate,
            "window function" => Kind::Window,
            _ => Kind::Table,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Table => "table",
            Kind::PartTable => "partitioned table",
            Kind::View => "view",
            Kind::MatView => "materialized view",
            Kind::Sequence => "sequence",
            Kind::Foreign => "foreign table",
            Kind::Function => "function",
            Kind::Procedure => "procedure",
            Kind::Aggregate => "aggregate",
            Kind::Window => "window function",
        }
    }

    /// Object type keyword in GRANT/REVOKE.
    pub fn grant_keyword(self) -> &'static str {
        match self {
            Kind::Sequence => "SEQUENCE",
            Kind::Procedure => "PROCEDURE",
            Kind::Function | Kind::Aggregate | Kind::Window => "FUNCTION",
            _ => "TABLE",
        }
    }

    /// Object type keyword in ALTER ... OWNER TO.
    pub fn alter_keyword(self) -> &'static str {
        match self {
            Kind::Table | Kind::PartTable => "TABLE",
            Kind::View => "VIEW",
            Kind::MatView => "MATERIALIZED VIEW",
            Kind::Sequence => "SEQUENCE",
            Kind::Foreign => "FOREIGN TABLE",
            Kind::Function | Kind::Window => "FUNCTION",
            Kind::Procedure => "PROCEDURE",
            Kind::Aggregate => "AGGREGATE",
        }
    }

    pub fn privs(self, v: i32) -> Vec<&'static str> {
        match self {
            Kind::Sequence => SEQUENCE_PRIVS.to_vec(),
            Kind::Function | Kind::Procedure | Kind::Aggregate | Kind::Window => ROUTINE_PRIVS.to_vec(),
            _ => table_privs(v),
        }
    }

    pub fn has_rls(self) -> bool {
        matches!(self, Kind::Table | Kind::PartTable)
    }
}

pub const RELKIND_LABEL: &str = "case c.relkind when 'r' then 'table' when 'p' then 'partitioned table' \
when 'v' then 'view' when 'm' then 'materialized view' when 'S' then 'sequence' when 'f' then 'foreign table' end";
pub const PROKIND_LABEL: &str = "case p.prokind when 'f' then 'function' when 'p' then 'procedure' \
when 'a' then 'aggregate' when 'w' then 'window function' end";

#[derive(Clone, Debug)]
pub struct Object {
    pub schema: String,
    /// Routines carry their argument list.
    pub name: String,
    pub kind: Kind,
    pub ident: String,
    pub owner: String,
    pub rls: bool,
    pub force_rls: bool,
    pub policies: i64,
    pub acl_default: bool,
    pub grants: Vec<Grant>,
    pub columns: Vec<(String, Vec<Grant>)>,
}

pub fn relations_sql() -> String {
    format!(
        "\
select c.oid, n.nspname::text, c.relname::text, {RELKIND_LABEL},
       quote_ident(n.nspname) || '.' || quote_ident(c.relname), pg_get_userbyid(c.relowner)::text,
       c.relrowsecurity, c.relforcerowsecurity, c.relacl is null,
       (select count(*) from pg_policy p where p.polrelid = c.oid)
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p','v','m','S','f')
order by 2, 3"
    )
}

pub fn relation_acl_sql() -> String {
    acl_sql(
        "c.oid",
        "pg_class c",
        "coalesce(c.relacl, acldefault(case when c.relkind = 'S' then 's' else 'r' end::\"char\", c.relowner))",
    )
}

pub fn column_acl_sql() -> String {
    format!(
        "\
select att.attrelid, att.attname::text, {GRANTEE}, {GRANTEE_IDENT}, pg_get_userbyid(a.grantor)::text,
       a.privilege_type, a.is_grantable
from pg_attribute att, aclexplode(att.attacl) a
where att.attacl is not null and not att.attisdropped
order by 1, att.attnum, a.grantee"
    )
}

pub fn routines_sql() -> String {
    format!(
        "\
select p.oid, n.nspname::text, p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
       {PROKIND_LABEL},
       quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || pg_get_function_identity_arguments(p.oid) || ')',
       pg_get_userbyid(p.proowner)::text, p.proacl is null
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
order by 2, 3"
    )
}

pub fn routine_acl_sql() -> String {
    acl_sql("p.oid", "pg_proc p", "coalesce(p.proacl, acldefault('f', p.proowner))")
}

/// One pg_default_acl entry: grants added to objects `creator` creates later.
#[derive(Clone, Debug)]
pub struct DefAcl {
    pub creator: String,
    pub creator_ident: String,
    /// None: applies in every schema and replaces the built-in defaults.
    pub schema: Option<String>,
    pub schema_ident: Option<String>,
    pub objtype: String,
    pub grants: Vec<Grant>,
}

pub const DEFACL_SQL: &str = "\
select d.oid, pg_get_userbyid(d.defaclrole)::text, quote_ident(pg_get_userbyid(d.defaclrole)),
       n.nspname::text, quote_ident(n.nspname), d.defaclobjtype::text
from pg_default_acl d left join pg_namespace n on n.oid = d.defaclnamespace
order by 2, 4 nulls first, 6";

pub fn defacl_acl_sql() -> String {
    acl_sql("d.oid", "pg_default_acl d", "d.defaclacl")
}

/// ALTER DEFAULT PRIVILEGES object types: (pg_default_acl code, keyword).
pub const DEFACL_TYPES: &[(&str, &str)] =
    &[("r", "TABLES"), ("S", "SEQUENCES"), ("f", "FUNCTIONS"), ("T", "TYPES"), ("n", "SCHEMAS"), ("L", "LARGE OBJECTS")];

pub fn defacl_keyword(code: &str) -> &'static str {
    DEFACL_TYPES.iter().find(|(c, _)| *c == code).map(|(_, k)| *k).unwrap_or("?")
}

pub fn defacl_privs(code: &str, v: i32) -> Vec<&'static str> {
    match code {
        "r" => table_privs(v),
        "S" => SEQUENCE_PRIVS.to_vec(),
        "f" => ROUTINE_PRIVS.to_vec(),
        "T" => vec!["USAGE"],
        "n" => SCHEMA_PRIVS.to_vec(),
        "L" => vec!["SELECT", "UPDATE"],
        _ => vec![],
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub name: String,
    pub permissive: bool,
    pub cmd: String,
    pub roles: Vec<String>,
    pub using: String,
    pub check: String,
}

#[derive(Clone, Debug)]
pub struct RlsTable {
    pub schema: String,
    pub name: String,
    pub owner: String,
    pub enabled: bool,
    pub forced: bool,
    pub policies: Vec<Policy>,
}

pub const RLS_SQL: &str = "\
select c.oid, n.nspname::text, c.relname::text, pg_get_userbyid(c.relowner)::text,
       c.relrowsecurity, c.relforcerowsecurity
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p')
  and (c.relrowsecurity or exists (select 1 from pg_policy p where p.polrelid = c.oid))
order by 2, 3";

pub const POLICIES_SQL: &str = "\
select p.polrelid, p.polname::text, p.polpermissive,
       case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT' when 'w' then 'UPDATE'
                     when 'd' then 'DELETE' else 'ALL' end,
       case when p.polroles = '{0}' then array['PUBLIC']
            else array(select pg_get_userbyid(r)::text from unnest(p.polroles) r) end,
       coalesce(pg_get_expr(p.polqual, p.polrelid), ''),
       coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
from pg_policy p
order by 1, 2";

/// An installed extension, or one whose files are on the server.
#[derive(Clone, Debug)]
pub struct Extension {
    pub name: String,
    /// None: not installed in this database.
    pub installed: Option<String>,
    pub default_version: Option<String>,
    pub schema: Option<String>,
    pub owner: Option<String>,
    pub trusted: bool,
    pub superuser: bool,
    pub relocatable: bool,
    pub requires: Vec<String>,
    pub comment: String,
}

impl Extension {
    /// What CREATE EXTENSION needs. `superuser` is also set on trusted extensions.
    pub fn needs(&self) -> &'static str {
        if self.trusted {
            "CREATE on db"
        } else if self.superuser {
            "superuser"
        } else {
            "its objects"
        }
    }
}

pub const EXTENSIONS_SQL: &str = "\
select coalesce(e.extname, a.name)::text, e.extversion::text, a.default_version::text,
       n.nspname::text, pg_get_userbyid(e.extowner)::text,
       coalesce(v.trusted, false), coalesce(v.superuser, true), coalesce(v.relocatable, e.extrelocatable, false),
       coalesce(v.requires::text[], '{}'), coalesce(a.comment, '')
from pg_extension e
full join pg_available_extensions a on a.name = e.extname
left join pg_namespace n on n.oid = e.extnamespace
left join pg_available_extension_versions v
  on v.name = coalesce(e.extname, a.name) and v.version = coalesce(e.extversion, a.default_version)
order by e.extname is null, 1";

#[derive(Default)]
pub struct Local {
    pub schemas: Vec<Schema>,
    pub objects: Vec<Object>,
    pub defacls: Vec<DefAcl>,
    pub rls: Vec<RlsTable>,
    pub extensions: Vec<Extension>,
}

pub fn load_local(c: &mut Client) -> Result<Local> {
    let mut acl = acl_map(c, &schema_acl_sql())?;
    let schemas = c
        .query(SCHEMAS_SQL, &[])?
        .iter()
        .map(|r| Schema {
            name: r.get(1),
            ident: r.get(2),
            owner: r.get(3),
            acl_default: r.get(4),
            relations: r.get(5),
            routines: r.get(6),
            comment: r.get(7),
            grants: acl.remove(&r.get(0)).unwrap_or_default(),
        })
        .collect();

    let mut acl = acl_map(c, &relation_acl_sql())?;
    let mut columns: HashMap<u32, Vec<(String, Vec<Grant>)>> = HashMap::new();
    for row in c.query(&column_acl_sql(), &[])? {
        let cols = columns.entry(row.get(0)).or_default();
        let col: String = row.get(1);
        if cols.last().is_none_or(|(c, _)| *c != col) {
            cols.push((col, Vec::new()));
        }
        add_grant(&mut cols.last_mut().unwrap().1, &row, 2);
    }
    let mut objects: Vec<Object> = c
        .query(&relations_sql(), &[])?
        .iter()
        .map(|r| Object {
            schema: r.get(1),
            name: r.get(2),
            kind: Kind::parse(r.get(3)),
            ident: r.get(4),
            owner: r.get(5),
            rls: r.get(6),
            force_rls: r.get(7),
            acl_default: r.get(8),
            policies: r.get(9),
            grants: acl.remove(&r.get(0)).unwrap_or_default(),
            columns: columns.remove(&r.get(0)).unwrap_or_default(),
        })
        .collect();
    let mut acl = acl_map(c, &routine_acl_sql())?;
    objects.extend(c.query(&routines_sql(), &[])?.iter().map(|r| Object {
        schema: r.get(1),
        name: r.get(2),
        kind: Kind::parse(r.get(3)),
        ident: r.get(4),
        owner: r.get(5),
        rls: false,
        force_rls: false,
        acl_default: r.get(6),
        policies: 0,
        grants: acl.remove(&r.get(0)).unwrap_or_default(),
        columns: Vec::new(),
    }));
    objects.sort_by(|a, b| (&a.schema, &a.name).cmp(&(&b.schema, &b.name)));

    let mut acl = acl_map(c, &defacl_acl_sql())?;
    let defacls = c
        .query(DEFACL_SQL, &[])?
        .iter()
        .map(|r| DefAcl {
            creator: r.get(1),
            creator_ident: r.get(2),
            schema: r.get(3),
            schema_ident: r.get(4),
            objtype: r.get(5),
            grants: acl.remove(&r.get(0)).unwrap_or_default(),
        })
        .collect();

    let mut policies: HashMap<u32, Vec<Policy>> = HashMap::new();
    for r in c.query(POLICIES_SQL, &[])? {
        policies.entry(r.get(0)).or_default().push(Policy {
            name: r.get(1),
            permissive: r.get(2),
            cmd: r.get(3),
            roles: r.get(4),
            using: r.get(5),
            check: r.get(6),
        });
    }
    let rls = c
        .query(RLS_SQL, &[])?
        .iter()
        .map(|r| RlsTable {
            schema: r.get(1),
            name: r.get(2),
            owner: r.get(3),
            enabled: r.get(4),
            forced: r.get(5),
            policies: policies.remove(&r.get(0)).unwrap_or_default(),
        })
        .collect();

    let extensions = c
        .query(EXTENSIONS_SQL, &[])?
        .iter()
        .map(|r| Extension {
            name: r.get(0),
            installed: r.get(1),
            default_version: r.get(2),
            schema: r.get(3),
            owner: r.get(4),
            trusted: r.get(5),
            superuser: r.get(6),
            relocatable: r.get(7),
            requires: r.get(8),
            comment: r.get(9),
        })
        .collect();

    Ok(Local { schemas, objects, defacls, rls, extensions })
}

// ---- effective access of one role ----

#[derive(Clone, Debug)]
pub struct Reach {
    pub name: String,
    /// Privileges of the role apply without SET ROLE.
    pub usage: bool,
    /// SET ROLE to it is allowed.
    pub set: bool,
}

#[derive(Clone, Debug)]
pub struct AccessItem {
    pub kind: String,
    pub schema: Option<String>,
    pub name: String,
    pub privs: Vec<String>,
    /// Privileges held on some columns only.
    pub column_privs: Vec<String>,
    pub owner: bool,
    /// Grants that apply to the role: direct, inherited, or PUBLIC.
    pub via: String,
    pub rls: bool,
    pub forced: bool,
    /// The layer above that makes these privileges unusable.
    pub blocked: Option<String>,
}

pub struct Access {
    pub role: Role,
    pub db: String,
    pub reach: Vec<Reach>,
    pub items: Vec<AccessItem>,
}

fn has(func: &str, obj: &str, privs: &[&str]) -> String {
    let items: Vec<String> =
        privs.iter().map(|p| format!("case when {func}($1::oid, {obj}, '{p}') then '{p}' end")).collect();
    format!("array_remove(array[{}]::text[], null)", items.join(", "))
}

fn via(acl: &str) -> String {
    format!(
        "coalesce((select string_agg(g, '; ' order by o) from (
           select a.grantee as o, {GRANTEE} || ': ' || string_agg(a.privilege_type, ', ') as g
           from aclexplode({acl}) a
           where case when a.grantee = 0 then true else pg_has_role($1::oid, a.grantee, 'USAGE') end
           group by a.grantee) s), '')"
    )
}

pub fn reach_sql(v: i32) -> &'static str {
    if v >= 160000 {
        "\
select r.rolname::text, pg_has_role($1::oid, r.oid, 'USAGE'), pg_has_role($1::oid, r.oid, 'SET')
from pg_roles r
where r.oid <> $1::oid and pg_has_role($1::oid, r.oid, 'MEMBER')
order by 1"
    } else {
        "\
select r.rolname::text, pg_has_role($1::oid, r.oid, 'USAGE'), pg_has_role($1::oid, r.oid, 'MEMBER')
from pg_roles r
where r.oid <> $1::oid and pg_has_role($1::oid, r.oid, 'MEMBER')
order by 1"
    }
}

/// Every object in the current database with what role $1 can do on it.
pub fn access_sql(v: i32) -> String {
    let none = "'{}'::text[]";
    let tables = table_privs(v);
    let col_privs = ["SELECT", "INSERT", "UPDATE", "REFERENCES"];
    format!(
        "\
select 'database', null::text, d.datname::text, {db_has}, {none}, pg_has_role($1::oid, d.datdba, 'USAGE'),
       {db_via}, false, false
from pg_database d where d.datallowconn
union all
select 'schema', n.nspname::text, n.nspname::text, {ns_has}, {none}, pg_has_role($1::oid, n.nspowner, 'USAGE'),
       {ns_via}, false, false
from pg_namespace n
union all
select {RELKIND_LABEL}, n.nspname::text, c.relname::text, {rel_has}, {col_has},
       pg_has_role($1::oid, c.relowner, 'USAGE'), {rel_via}, c.relrowsecurity, c.relforcerowsecurity
from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind in ('r','p','v','m','f')
union all
select 'sequence', n.nspname::text, c.relname::text, {seq_has}, {none},
       pg_has_role($1::oid, c.relowner, 'USAGE'), {seq_via}, false, false
from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind = 'S'
union all
select {PROKIND_LABEL}, n.nspname::text, p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
       {fn_has}, {none}, pg_has_role($1::oid, p.proowner, 'USAGE'), {fn_via}, false, false
from pg_proc p join pg_namespace n on n.oid = p.pronamespace",
        db_has = has("has_database_privilege", "d.oid", DATABASE_PRIVS),
        db_via = via("coalesce(d.datacl, acldefault('d', d.datdba))"),
        ns_has = has("has_schema_privilege", "n.oid", SCHEMA_PRIVS),
        ns_via = via("coalesce(n.nspacl, acldefault('n', n.nspowner))"),
        rel_has = has("has_table_privilege", "c.oid", &tables),
        col_has = has("has_any_column_privilege", "c.oid", &col_privs),
        rel_via = via("coalesce(c.relacl, acldefault('r', c.relowner))"),
        seq_has = has("has_sequence_privilege", "c.oid", SEQUENCE_PRIVS),
        seq_via = via("coalesce(c.relacl, acldefault('s', c.relowner))"),
        fn_has = has("has_function_privilege", "p.oid", ROUTINE_PRIVS),
        fn_via = via("coalesce(p.proacl, acldefault('f', p.proowner))"),
    )
}

pub fn load_access(c: &mut Client, v: i32, role: &Role, db: &str) -> Result<Access> {
    let reach = if role.superuser {
        Vec::new()
    } else {
        c.query(reach_sql(v), &[&role.oid])?
            .iter()
            .map(|r| Reach { name: r.get(0), usage: r.get(1), set: r.get(2) })
            .collect()
    };
    let mut items: Vec<AccessItem> = c
        .query(&access_sql(v), &[&role.oid])?
        .iter()
        .map(|r| {
            let privs: Vec<String> = r.get(3);
            let cols: Vec<String> = r.get(4);
            AccessItem {
                kind: r.get(0),
                schema: r.get(1),
                name: r.get(2),
                column_privs: cols.into_iter().filter(|p| !privs.contains(p)).collect(),
                privs,
                owner: r.get(5),
                via: r.get(6),
                rls: r.get(7),
                forced: r.get(8),
                blocked: None,
            }
        })
        .collect();

    let connect = items.iter().any(|i| i.kind == "database" && i.name == db && i.privs.iter().any(|p| p == "CONNECT"));
    let usable: HashSet<String> = items
        .iter()
        .filter(|i| i.kind == "schema" && i.privs.iter().any(|p| p == "USAGE"))
        .map(|i| i.name.clone())
        .collect();
    for i in items.iter_mut().filter(|i| i.kind != "database") {
        if !connect {
            i.blocked = Some(format!("no CONNECT on database {db}"));
        } else if i.kind != "schema"
            && let Some(s) = &i.schema
            && !usable.contains(s)
        {
            i.blocked = Some(format!("no USAGE on schema {s}"));
        }
    }
    let rank = |k: &str| match k {
        "database" => 0,
        "schema" => 1,
        _ => 2,
    };
    items.sort_by(|a, b| (rank(&a.kind), &a.schema, &a.name).cmp(&(rank(&b.kind), &b.schema, &b.name)));
    Ok(Access { role: role.clone(), db: db.to_string(), reach, items })
}

// ---- what keeps a role from being dropped ----

/// One pg_shdepend entry of a role.
#[derive(Clone, Debug)]
pub struct RoleDep {
    /// Database the object is in; empty for cluster-wide objects (databases, tablespaces, parameters).
    pub db: String,
    /// 'a' privilege, 'o' owner, 'r' policy target, 'i' initial privilege of an extension.
    pub deptype: String,
    /// pg_identify_object type, e.g. "table", "table column", "default acl".
    pub kind: String,
    /// Quoted by the server. For a column, its table.
    pub ident: String,
    pub column: Option<String>,
    /// For "default acl": quoted creator, quoted schema (None for all schemas), defaclobjtype.
    pub defacl: Option<(String, Option<String>, String)>,
    /// pg_describe_object.
    pub what: String,
}

const ROLE_DEP_DBS_SQL: &str = "\
select distinct d.datname::text
from pg_shdepend s join pg_database d on d.oid = s.dbid
where s.refclassid = 'pg_authid'::regclass and s.refobjid = $1 and d.datname <> current_database()
order by 1";

/// Entries in the current database, and cluster-wide ones when $2.
const ROLE_DEPS_SQL: &str = "\
select s.deptype::text, o.type, case when s.objsubid <> 0 then t.identity else o.identity end,
       case when s.objsubid <> 0 and s.classid = 'pg_class'::regclass
            then (select quote_ident(attname) from pg_attribute where attrelid = s.objid and attnum = s.objsubid) end,
       quote_ident(pg_get_userbyid(a.defaclrole)), nullif(a.defaclnamespace, 0)::regnamespace::text,
       a.defaclobjtype::text, pg_describe_object(s.classid, s.objid, s.objsubid), s.dbid = 0
from pg_shdepend s
cross join lateral pg_identify_object(s.classid, s.objid, s.objsubid) o
cross join lateral pg_identify_object(s.classid, s.objid, 0) t
left join pg_default_acl a on s.classid = 'pg_default_acl'::regclass and a.oid = s.objid
where s.refclassid = 'pg_authid'::regclass and s.refobjid = $1
  and (s.dbid = (select oid from pg_database where datname = current_database()) or (s.dbid = 0 and $2))
order by s.dbid <> 0, 8";

/// Databases other than the connected one with entries for `role`. Naming those entries needs a
/// connection to each.
pub fn role_dep_dbs(c: &mut Client, role: u32) -> Result<Vec<String>> {
    Ok(c.query(ROLE_DEP_DBS_SQL, &[&role])?.iter().map(|r| r.get(0)).collect())
}

/// Entries of `role` in `db`, the database `c` is connected to.
pub fn role_deps(c: &mut Client, role: u32, db: &str, shared: bool) -> Result<Vec<RoleDep>> {
    Ok(c.query(ROLE_DEPS_SQL, &[&role, &shared])?
        .iter()
        .map(|r| {
            let creator: Option<String> = r.get(4);
            RoleDep {
                db: if r.get(8) { String::new() } else { db.to_string() },
                deptype: r.get(0),
                kind: r.get(1),
                ident: r.get(2),
                column: r.get(3),
                defacl: creator.map(|c| (c, r.get(5), r.get::<_, Option<String>>(6).unwrap_or_default())),
                what: r.get(7),
            }
        })
        .collect())
}
