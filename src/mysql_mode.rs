// Licensed under Apache-2.0 (Genesis extension to sqlparser-rs)

//! Session-aware MySQL parsing mode flags.
//!
//! These flags affect how the MySQL dialect parses SQL. They must be set
//! before parsing based on the connection's sql_mode.

/// MySQL sql_mode flags that affect parsing behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MySqlModeFlags(u32);

impl MySqlModeFlags {
    /// Double-quote is an identifier quote, not a string literal quote.
    pub const ANSI_QUOTES: u32 = 1 << 0;
    /// Backslash has no special meaning in string literals.
    pub const NO_BACKSLASH_ESCAPES: u32 = 1 << 1;
    /// `||` is string concatenation (like ANSI SQL), not logical OR.
    pub const PIPES_AS_CONCAT: u32 = 1 << 2;
    /// Permit spaces between function name and `(` for built-in functions.
    pub const IGNORE_SPACE: u32 = 1 << 3;
    /// `NOT` has higher precedence (MySQL pre-5.7 behavior).
    pub const HIGH_NOT_PRECEDENCE: u32 = 1 << 4;
    /// `REAL` is `FLOAT` instead of `DOUBLE`.
    pub const REAL_AS_FLOAT: u32 = 1 << 5;

    /// Create empty flags (MySQL 8.0 default).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(self) -> u32 {
        self.0
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

/// Subset of mode flags that affect the lexer/tokenizer.
/// Used by the parameterizer for charset-safe literal extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MySqlLexerMode {
    /// Double-quote is an identifier quote.
    pub ansi_quotes: bool,
    /// Backslash has no special meaning in string literals.
    pub no_backslash_escapes: bool,
}

impl From<MySqlModeFlags> for MySqlLexerMode {
    fn from(flags: MySqlModeFlags) -> Self {
        Self {
            ansi_quotes: flags.contains(MySqlModeFlags::ANSI_QUOTES),
            no_backslash_escapes: flags.contains(MySqlModeFlags::NO_BACKSLASH_ESCAPES),
        }
    }
}

/// Parse a sql_mode string (e.g. "ANSI_QUOTES,NO_BACKSLASH_ESCAPES") into flags.
pub fn parse_sql_mode(sql_mode: &str) -> MySqlModeFlags {
    let mut flags = MySqlModeFlags::empty();
    for part in sql_mode.split(',') {
        match part.trim().to_uppercase().as_str() {
            "ANSI_QUOTES" => flags.insert(MySqlModeFlags::ANSI_QUOTES),
            "NO_BACKSLASH_ESCAPES" => flags.insert(MySqlModeFlags::NO_BACKSLASH_ESCAPES),
            "PIPES_AS_CONCAT" => flags.insert(MySqlModeFlags::PIPES_AS_CONCAT),
            "IGNORE_SPACE" => flags.insert(MySqlModeFlags::IGNORE_SPACE),
            "HIGH_NOT_PRECEDENCE" | "NO_FIELD_OPTIONS" => {
                flags.insert(MySqlModeFlags::HIGH_NOT_PRECEDENCE);
            }
            "REAL_AS_FLOAT" => flags.insert(MySqlModeFlags::REAL_AS_FLOAT),
            "ANSI" => {
                flags.insert(MySqlModeFlags::ANSI_QUOTES);
                flags.insert(MySqlModeFlags::PIPES_AS_CONCAT);
                flags.insert(MySqlModeFlags::REAL_AS_FLOAT);
            }
            _ => {} // Ignore unknown modes (STRICT_TRANS_TABLES, etc.)
        }
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_mode() {
        assert_eq!(parse_sql_mode(""), MySqlModeFlags::empty());
    }

    #[test]
    fn parse_ansi_quotes() {
        let flags = parse_sql_mode("ANSI_QUOTES");
        assert!(flags.contains(MySqlModeFlags::ANSI_QUOTES));
        assert!(!flags.contains(MySqlModeFlags::NO_BACKSLASH_ESCAPES));
    }

    #[test]
    fn parse_multiple_modes() {
        let flags = parse_sql_mode("ANSI_QUOTES,NO_BACKSLASH_ESCAPES,STRICT_TRANS_TABLES");
        assert!(flags.contains(MySqlModeFlags::ANSI_QUOTES));
        assert!(flags.contains(MySqlModeFlags::NO_BACKSLASH_ESCAPES));
    }

    #[test]
    fn parse_ansi_composite() {
        let flags = parse_sql_mode("ANSI");
        assert!(flags.contains(MySqlModeFlags::ANSI_QUOTES));
        assert!(flags.contains(MySqlModeFlags::PIPES_AS_CONCAT));
        assert!(flags.contains(MySqlModeFlags::REAL_AS_FLOAT));
    }

    #[test]
    fn lexer_mode_from_flags() {
        let mut flags = MySqlModeFlags::empty();
        flags.insert(MySqlModeFlags::ANSI_QUOTES);
        flags.insert(MySqlModeFlags::PIPES_AS_CONCAT);
        let lexer: MySqlLexerMode = flags.into();
        assert!(lexer.ansi_quotes);
        assert!(!lexer.no_backslash_escapes);
    }
}
