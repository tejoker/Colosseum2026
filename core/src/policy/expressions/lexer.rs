//! Hand-rolled lexer for the invariant expression grammar.
//!
//! Yields a flat `Vec<TokenWithPos>` so the parser can use simple index-based
//! lookahead. Position tracking is byte-offset based — fine for ASCII source,
//! which is all the grammar admits (identifiers must be `[A-Za-z_][A-Za-z0-9_]*`,
//! strings are `'…'` only). We deliberately do **not** allocate a streaming
//! iterator: invariant expressions are bounded (typically < 200 chars) and a
//! one-shot pass keeps error reporting trivial.

use std::fmt;

use super::parser::BinOp;

/// One token plus its byte offset into the source string.
///
/// Position is the offset of the first character of the token. Useful for
/// pointing at the exact column of a parse error.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenWithPos {
    /// The token kind + payload.
    pub token: Token,
    /// Byte offset of the token's first character in the source string.
    pub pos: usize,
}

/// All token kinds the lexer emits.
///
/// `Op(BinOp)` carries comparison + arithmetic operators; the parser treats
/// `In`/`And`/`Or`/`Not` separately because their precedence differs.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Bare identifier — `spend_total`, `max_budget_usd`, `action`, etc.
    Ident(String),
    /// Numeric literal — integer or float, both stored as `f64`.
    Num(f64),
    /// String literal — single-quoted, no escapes needed for the grammar.
    Str(String),
    /// `(` — opens a grouping or a function-call argument list or a tuple literal.
    LParen,
    /// `)` — closes the matching `(`.
    RParen,
    /// `[` — opens a list literal.
    LBracket,
    /// `]` — closes the matching `[`.
    RBracket,
    /// `,` — separator inside argument lists, lists, or tuples.
    Comma,
    /// `:` — separates kwarg name from value in a function call.
    Colon,
    /// Comparison or arithmetic operator (see [`BinOp`]). `And`/`Or` are
    /// emitted as dedicated tokens — they live outside `BinOp` in the lexer.
    Op(BinOp),
    /// `in` — membership test keyword.
    In,
    /// `&&` or `and` — logical-and.
    And,
    /// `||` or `or` — logical-or.
    Or,
    /// `!` or `not` — logical-not unary operator.
    Not,
    /// `true` literal.
    True,
    /// `false` literal.
    False,
    /// End-of-input sentinel — convenient for the parser's lookahead.
    Eof,
}

/// Lex-time errors with the byte offset where the problem was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexError {
    /// An unexpected character (anything outside the small grammar's alphabet).
    UnexpectedChar { ch: char, pos: usize },
    /// String literal opened with `'` but never closed.
    UnterminatedString { pos: usize },
    /// Number that doesn't parse as `f64` (e.g. `1.2.3`).
    InvalidNumber { src: String, pos: usize },
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LexError::UnexpectedChar { ch, pos } => {
                write!(f, "unexpected character '{ch}' at byte {pos}")
            }
            LexError::UnterminatedString { pos } => {
                write!(f, "unterminated string literal starting at byte {pos}")
            }
            LexError::InvalidNumber { src, pos } => {
                write!(f, "invalid numeric literal '{src}' at byte {pos}")
            }
        }
    }
}

impl std::error::Error for LexError {}

/// Tokenize the input string in one pass.
///
/// Always returns a [`Token::Eof`] as the final entry — the parser uses it as
/// a stable end-of-stream sentinel so it never needs a length check.
pub fn lex(input: &str) -> Result<Vec<TokenWithPos>, LexError> {
    let bytes = input.as_bytes();
    let mut out: Vec<TokenWithPos> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        // Skip ASCII whitespace.
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        match c {
            '(' => {
                out.push(TokenWithPos { token: Token::LParen, pos: start });
                i += 1;
            }
            ')' => {
                out.push(TokenWithPos { token: Token::RParen, pos: start });
                i += 1;
            }
            '[' => {
                out.push(TokenWithPos { token: Token::LBracket, pos: start });
                i += 1;
            }
            ']' => {
                out.push(TokenWithPos { token: Token::RBracket, pos: start });
                i += 1;
            }
            ',' => {
                out.push(TokenWithPos { token: Token::Comma, pos: start });
                i += 1;
            }
            ':' => {
                out.push(TokenWithPos { token: Token::Colon, pos: start });
                i += 1;
            }
            '+' => {
                out.push(TokenWithPos { token: Token::Op(BinOp::Add), pos: start });
                i += 1;
            }
            '-' => {
                out.push(TokenWithPos { token: Token::Op(BinOp::Sub), pos: start });
                i += 1;
            }
            '=' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(TokenWithPos { token: Token::Op(BinOp::Eq), pos: start });
                    i += 2;
                } else {
                    return Err(LexError::UnexpectedChar { ch: '=', pos: start });
                }
            }
            '!' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(TokenWithPos { token: Token::Op(BinOp::Neq), pos: start });
                    i += 2;
                } else {
                    out.push(TokenWithPos { token: Token::Not, pos: start });
                    i += 1;
                }
            }
            '<' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(TokenWithPos { token: Token::Op(BinOp::Lte), pos: start });
                    i += 2;
                } else {
                    out.push(TokenWithPos { token: Token::Op(BinOp::Lt), pos: start });
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(TokenWithPos { token: Token::Op(BinOp::Gte), pos: start });
                    i += 2;
                } else {
                    out.push(TokenWithPos { token: Token::Op(BinOp::Gt), pos: start });
                    i += 1;
                }
            }
            '&' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    out.push(TokenWithPos { token: Token::And, pos: start });
                    i += 2;
                } else {
                    return Err(LexError::UnexpectedChar { ch: '&', pos: start });
                }
            }
            '|' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                    out.push(TokenWithPos { token: Token::Or, pos: start });
                    i += 2;
                } else {
                    return Err(LexError::UnexpectedChar { ch: '|', pos: start });
                }
            }
            '\'' => {
                // String literal — no escapes (the grammar doesn't need them
                // for the policy expressions we accept).
                let body_start = i + 1;
                let mut j = body_start;
                while j < bytes.len() && bytes[j] != b'\'' {
                    j += 1;
                }
                if j >= bytes.len() {
                    return Err(LexError::UnterminatedString { pos: start });
                }
                let s = std::str::from_utf8(&bytes[body_start..j])
                    .expect("lexer source is utf-8")
                    .to_string();
                out.push(TokenWithPos { token: Token::Str(s), pos: start });
                i = j + 1;
            }
            ch if ch.is_ascii_digit() => {
                let mut j = i;
                while j < bytes.len()
                    && ((bytes[j] as char).is_ascii_digit() || bytes[j] == b'.')
                {
                    j += 1;
                }
                let raw = &input[i..j];
                let n: f64 = raw.parse().map_err(|_| LexError::InvalidNumber {
                    src: raw.to_string(),
                    pos: start,
                })?;
                out.push(TokenWithPos { token: Token::Num(n), pos: start });
                i = j;
            }
            ch if ch.is_ascii_alphabetic() || ch == '_' => {
                let mut j = i;
                while j < bytes.len()
                    && ((bytes[j] as char).is_ascii_alphanumeric() || bytes[j] == b'_')
                {
                    j += 1;
                }
                // Dotted identifier extension: `action.tool` is one token.
                // Only consume the `.` if the next char starts another
                // identifier segment (lookahead-safe; no member-access
                // ambiguity because numbers can't follow `.` in idents).
                while j + 1 < bytes.len()
                    && bytes[j] == b'.'
                    && ((bytes[j + 1] as char).is_ascii_alphabetic() || bytes[j + 1] == b'_')
                {
                    j += 1; // consume '.'
                    while j < bytes.len()
                        && ((bytes[j] as char).is_ascii_alphanumeric() || bytes[j] == b'_')
                    {
                        j += 1;
                    }
                }
                let word = &input[i..j];
                let tok = match word {
                    "true" => Token::True,
                    "false" => Token::False,
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    "in" => Token::In,
                    _ => Token::Ident(word.to_string()),
                };
                out.push(TokenWithPos { token: tok, pos: start });
                i = j;
            }
            other => return Err(LexError::UnexpectedChar { ch: other, pos: start }),
        }
    }
    out.push(TokenWithPos { token: Token::Eof, pos: bytes.len() });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(toks: &[TokenWithPos]) -> Vec<Token> {
        toks.iter().map(|t| t.token.clone()).collect()
    }

    #[test]
    fn lexes_simple_identifier_and_eof() {
        let toks = lex("spend_total").unwrap();
        assert_eq!(
            kinds(&toks),
            vec![Token::Ident("spend_total".into()), Token::Eof]
        );
        assert_eq!(toks[0].pos, 0);
    }

    #[test]
    fn lexes_numbers_int_and_float() {
        let toks = lex("1 2.5 0.0").unwrap();
        assert_eq!(
            kinds(&toks),
            vec![Token::Num(1.0), Token::Num(2.5), Token::Num(0.0), Token::Eof]
        );
    }

    #[test]
    fn lexes_string_literal() {
        let toks = lex("'EUR'").unwrap();
        assert_eq!(kinds(&toks), vec![Token::Str("EUR".into()), Token::Eof]);
    }

    #[test]
    fn lexes_all_comparison_operators() {
        let toks = lex("== != <= < >= >").unwrap();
        assert_eq!(
            kinds(&toks),
            vec![
                Token::Op(BinOp::Eq),
                Token::Op(BinOp::Neq),
                Token::Op(BinOp::Lte),
                Token::Op(BinOp::Lt),
                Token::Op(BinOp::Gte),
                Token::Op(BinOp::Gt),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lexes_boolean_operators_both_spellings() {
        let toks = lex("&& || ! and or not").unwrap();
        assert_eq!(
            kinds(&toks),
            vec![
                Token::And,
                Token::Or,
                Token::Not,
                Token::And,
                Token::Or,
                Token::Not,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lexes_parens_brackets_comma_colon() {
        let toks = lex("( ) [ ] , :").unwrap();
        assert_eq!(
            kinds(&toks),
            vec![
                Token::LParen,
                Token::RParen,
                Token::LBracket,
                Token::RBracket,
                Token::Comma,
                Token::Colon,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn lexes_keywords_in_true_false() {
        let toks = lex("in true false").unwrap();
        assert_eq!(
            kinds(&toks),
            vec![Token::In, Token::True, Token::False, Token::Eof]
        );
    }

    #[test]
    fn tracks_positions_across_whitespace() {
        let toks = lex("  a   ==   1").unwrap();
        // Positions are the byte offset of the first char of each token.
        assert_eq!(toks[0].pos, 2);
        assert_eq!(toks[1].pos, 6);
        assert_eq!(toks[2].pos, 11);
    }

    #[test]
    fn unterminated_string_is_an_error() {
        let err = lex("'unfinished").unwrap_err();
        assert!(matches!(err, LexError::UnterminatedString { pos: 0 }));
    }

    #[test]
    fn unexpected_character_is_an_error() {
        let err = lex("a @ b").unwrap_err();
        match err {
            LexError::UnexpectedChar { ch, pos } => {
                assert_eq!(ch, '@');
                assert_eq!(pos, 2);
            }
            other => panic!("expected UnexpectedChar, got {other:?}"),
        }
    }

    #[test]
    fn lexes_full_invariant_expression() {
        // End-to-end on a real fixture invariant.
        let toks = lex("payment_currency in ('EUR', 'USD')").unwrap();
        assert_eq!(
            kinds(&toks),
            vec![
                Token::Ident("payment_currency".into()),
                Token::In,
                Token::LParen,
                Token::Str("EUR".into()),
                Token::Comma,
                Token::Str("USD".into()),
                Token::RParen,
                Token::Eof,
            ]
        );
    }
}
