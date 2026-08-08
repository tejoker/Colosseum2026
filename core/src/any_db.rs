//! One database handle over SQLite and PostgreSQL.
//!
//! The 277 direct rusqlite call sites are synchronous code inside async
//! handlers. `Repo` uses sqlx, which is async, so porting a call site to it
//! means rewriting the function — and its callers — as async. That is the
//! version of this project measured in months.
//!
//! So this uses the BLOCKING postgres driver instead. A call site keeps its
//! shape: `db.execute(sql, params)` / `db.query_row(sql, params, |r| …)`, with
//! the same borrow pattern and no `.await`. What changes is the row type, which
//! is why [`AnyRow`] exists.
//!
//! SQL is translated on the way through by [`crate::sql_translate`], so call
//! sites keep writing the SQLite dialect they already use.
//!
//! Deliberately NOT a general-purpose abstraction: it covers the shapes this
//! codebase actually uses. Anything else should fail to compile rather than be
//! silently approximated.

use crate::sql_translate::to_postgres;

/// A value that can be bound to a statement on either backend.
///
/// Small closed set on purpose: every bound parameter in this codebase is a
/// string, integer, float, bool, blob or null. A closed enum makes the
/// conversion total, and an unsupported type a compile error rather than a
/// runtime surprise.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
    Bool(bool),
}

impl From<i64> for SqlValue {
    fn from(v: i64) -> Self {
        SqlValue::Int(v)
    }
}
impl From<i32> for SqlValue {
    fn from(v: i32) -> Self {
        SqlValue::Int(v as i64)
    }
}
impl From<f64> for SqlValue {
    fn from(v: f64) -> Self {
        SqlValue::Real(v)
    }
}
impl From<bool> for SqlValue {
    fn from(v: bool) -> Self {
        SqlValue::Bool(v)
    }
}
impl From<&str> for SqlValue {
    fn from(v: &str) -> Self {
        SqlValue::Text(v.to_string())
    }
}
impl From<String> for SqlValue {
    fn from(v: String) -> Self {
        SqlValue::Text(v)
    }
}
impl From<&String> for SqlValue {
    fn from(v: &String) -> Self {
        SqlValue::Text(v.clone())
    }
}
impl From<Vec<u8>> for SqlValue {
    fn from(v: Vec<u8>) -> Self {
        SqlValue::Blob(v)
    }
}
impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(inner) => inner.into(),
            None => SqlValue::Null,
        }
    }
}

/// Column access that reads the same on both backends.
///
/// Typed getters rather than a generic `get::<T>()`: the backends disagree about
/// which Rust types a column maps to (SQLite is dynamically typed and hands back
/// i64 for anything integral; Postgres is strict and distinguishes INT4/INT8/
/// BOOL). Naming the intent at the call site removes that ambiguity.
pub trait AnyRow {
    fn get_i64(&self, idx: usize) -> Result<i64, String>;
    fn get_string(&self, idx: usize) -> Result<String, String>;
    fn get_bool(&self, idx: usize) -> Result<bool, String>;
    fn get_f64(&self, idx: usize) -> Result<f64, String>;
    fn get_blob(&self, idx: usize) -> Result<Vec<u8>, String>;
    fn get_opt_string(&self, idx: usize) -> Result<Option<String>, String>;
    fn get_opt_i64(&self, idx: usize) -> Result<Option<i64>, String>;
}

impl AnyRow for rusqlite::Row<'_> {
    fn get_i64(&self, idx: usize) -> Result<i64, String> {
        self.get::<_, i64>(idx).map_err(|e| e.to_string())
    }
    fn get_string(&self, idx: usize) -> Result<String, String> {
        self.get::<_, String>(idx).map_err(|e| e.to_string())
    }
    fn get_bool(&self, idx: usize) -> Result<bool, String> {
        // SQLite stores booleans as 0/1 integers; some columns are declared
        // BOOLEAN and some INTEGER, and rusqlite will refuse the wrong one, so
        // accept either rather than making every call site care.
        match self.get::<_, i64>(idx) {
            Ok(v) => Ok(v != 0),
            Err(_) => self.get::<_, bool>(idx).map_err(|e| e.to_string()),
        }
    }
    fn get_f64(&self, idx: usize) -> Result<f64, String> {
        self.get::<_, f64>(idx).map_err(|e| e.to_string())
    }
    fn get_blob(&self, idx: usize) -> Result<Vec<u8>, String> {
        self.get::<_, Vec<u8>>(idx).map_err(|e| e.to_string())
    }
    fn get_opt_string(&self, idx: usize) -> Result<Option<String>, String> {
        self.get::<_, Option<String>>(idx)
            .map_err(|e| e.to_string())
    }
    fn get_opt_i64(&self, idx: usize) -> Result<Option<i64>, String> {
        self.get::<_, Option<i64>>(idx).map_err(|e| e.to_string())
    }
}

/// Which backend a handle talks to. Kept separate from the handle so callers can
/// branch on it for the few places where behaviour genuinely differs (retry on
/// serialization failure, for instance) without matching on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

impl Backend {
    /// The statement this backend should actually receive.
    pub fn prepare_sql(&self, sql: &str) -> String {
        match self {
            Backend::Sqlite => sql.to_string(),
            Backend::Postgres => to_postgres(sql),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_statements_pass_through_untouched() {
        let sql = "INSERT OR IGNORE INTO t (a) VALUES (?1)";
        assert_eq!(Backend::Sqlite.prepare_sql(sql), sql);
    }

    #[test]
    fn postgres_statements_are_translated() {
        assert_eq!(
            Backend::Postgres.prepare_sql("SELECT IFNULL(a, 0) FROM t WHERE b = ?1"),
            "SELECT COALESCE(a, 0) FROM t WHERE b = $1"
        );
    }

    #[test]
    fn values_convert_from_the_types_call_sites_actually_bind() {
        assert_eq!(SqlValue::from(7i64), SqlValue::Int(7));
        assert_eq!(SqlValue::from("x"), SqlValue::Text("x".into()));
        assert_eq!(SqlValue::from(true), SqlValue::Bool(true));
        assert_eq!(SqlValue::from(None::<i64>), SqlValue::Null);
        assert_eq!(SqlValue::from(Some(3i64)), SqlValue::Int(3));
        assert_eq!(SqlValue::from(vec![1u8, 2]), SqlValue::Blob(vec![1, 2]));
    }

    #[test]
    fn sqlite_rows_read_integer_booleans() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (i INTEGER, s TEXT, b INTEGER, f REAL, blob BLOB, opt TEXT);
             INSERT INTO t VALUES (42, 'hello', 1, 1.5, X'0102', NULL);",
        )
        .unwrap();
        conn.query_row("SELECT i, s, b, f, blob, opt FROM t", [], |r| {
            assert_eq!(r.get_i64(0).unwrap(), 42);
            assert_eq!(r.get_string(1).unwrap(), "hello");
            assert!(r.get_bool(2).unwrap(), "0/1 integers must read as bool");
            assert_eq!(r.get_f64(3).unwrap(), 1.5);
            assert_eq!(r.get_blob(4).unwrap(), vec![1u8, 2]);
            assert_eq!(r.get_opt_string(5).unwrap(), None);
            Ok(())
        })
        .unwrap();
    }
}
