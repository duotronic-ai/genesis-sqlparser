// Licensed under Apache-2.0 (Genesis extension to sqlparser-rs)

//! Translation-aware AST metadata.
//!
//! Embedded during parsing to eliminate separate analysis passes.
//! The parser detects syntax-local facts (statement kind, insert strategy,
//! placeholder positions) so the translator consumes them directly.

use crate::ast::Statement;

/// Coarse statement classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    /// SELECT query.
    Select,
    /// INSERT statement.
    Insert,
    /// UPDATE statement.
    Update,
    /// DELETE statement.
    Delete,
    /// CREATE TABLE.
    CreateTable,
    /// ALTER TABLE.
    AlterTable,
    /// DROP TABLE.
    DropTable,
    /// SHOW command.
    Show,
    /// SET command.
    Set,
    /// USE database.
    Use,
    /// BEGIN transaction.
    Begin,
    /// COMMIT transaction.
    Commit,
    /// ROLLBACK transaction.
    Rollback,
    /// SAVEPOINT.
    Savepoint,
    /// Anything else.
    Other,
}

/// Insert conflict handling strategy, detected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertStrategy {
    /// Plain INSERT.
    Plain,
    /// INSERT IGNORE — suppress duplicate key errors.
    Ignore,
    /// REPLACE INTO — delete + insert on conflict.
    Replace,
    /// INSERT ... ON DUPLICATE KEY UPDATE.
    OnDuplicateKeyUpdate,
}

/// Statement-level flags detected during parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StmtFlags(u32);

impl StmtFlags {
    /// Uses SQL_CALC_FOUND_ROWS.
    pub const HAS_FOUND_ROWS: u32 = 1 << 0;
    /// Is a DDL statement.
    pub const IS_DDL: u32 = 1 << 1;
    /// Contains a subquery.
    pub const HAS_SUBQUERY: u32 = 1 << 2;
    /// Uses LAST_INSERT_ID().
    pub const HAS_LAST_INSERT_ID: u32 = 1 << 3;
    /// Uses user variables (@var).
    pub const HAS_USER_VARS: u32 = 1 << 4;
    /// Contains GROUP_CONCAT or similar aggregate needing rewrite.
    pub const HAS_AGGREGATE_REWRITE: u32 = 1 << 5;

    /// Create empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if a flag is set.
    pub const fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Set a flag.
    pub fn insert(&mut self, flag: u32) {
        self.0 |= flag;
    }
}

/// Metadata collected during parsing, attached to the parsed statement.
#[derive(Debug, Clone)]
pub struct TranslationMetadata {
    /// Coarse statement classification.
    pub stmt_kind: StatementKind,
    /// Statement-level flags.
    pub stmt_flags: StmtFlags,
    /// Insert strategy (if applicable).
    pub insert_strategy: Option<InsertStrategy>,
    /// Number of `?` placeholders found.
    pub placeholder_count: u16,
}

impl TranslationMetadata {
    /// Create metadata for a simple statement with no special flags.
    pub fn simple(kind: StatementKind) -> Self {
        Self {
            stmt_kind: kind,
            stmt_flags: StmtFlags::empty(),
            insert_strategy: None,
            placeholder_count: 0,
        }
    }
}

/// A parsed statement with attached translation metadata.
#[derive(Debug, Clone)]
pub struct ParsedStatement {
    /// The parsed AST statement.
    pub stmt: Statement,
    /// Translation metadata detected during parsing.
    pub meta: TranslationMetadata,
}
