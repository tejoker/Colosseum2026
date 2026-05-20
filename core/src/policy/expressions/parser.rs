//! Recursive-descent parser for the invariant expression grammar.
//!
//! Pratt-style precedence climb. The grammar is documented in
//! [`super`]. Errors carry the byte offset of the offending token so callers
//! can point to the exact column.

use std::fmt;

use super::lexer::{lex, LexError, Token, TokenWithPos};

/// Binary operators recognised by the parser.
///
/// `And`/`Or` show up here in the AST even though the lexer emits them as
/// dedicated `Token::And`/`Token::Or` (they have unique precedence). Keeping
/// them in one enum simplifies the evaluator's pattern match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `==` — equality.
    Eq,
    /// `!=` — inequality.
    Neq,
    /// `<` — less-than.
    Lt,
    /// `<=` — less-than-or-equal.
    Lte,
    /// `>` — greater-than.
    Gt,
    /// `>=` — greater-than-or-equal.
    Gte,
    /// `+` — numeric addition.
    Add,
    /// `-` — numeric subtraction.
    Sub,
    /// `&&` / `and` — logical conjunction.
    And,
    /// `||` / `or` — logical disjunction.
    Or,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// `!` / `not` — logical negation.
    Not,
    /// Unary `-` — numeric negation.
    Neg,
}

/// AST node for a parsed expression.
///
/// The variants are small and `Box`-allocated for recursive children so the
/// total AST size stays bounded for the bounded inputs we accept (invariant
/// strings are typically < 200 chars).
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Bare identifier (`spend_total`, `payment_currency`, …). Resolved at
    /// eval-time against [`super::eval::EvalEnv`].
    Ident(String),
    /// Numeric literal (`1`, `2.5`, `-3` is `Unary(Neg, Num(3))`).
    Num(f64),
    /// String literal (`'EUR'`).
    Str(String),
    /// Boolean literal (`true` / `false`).
    Bool(bool),
    /// Tuple or list literal — `(a, b, c)` (parenthesised, requires ≥1 comma)
    /// or `[a, b, c]`.
    List(Vec<Expr>),
    /// Binary operation. Operator + two children.
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// Unary operation. Operator + one child.
    Unary(UnaryOp, Box<Expr>),
    /// Membership test — `a in [b, c]` or `a in (b, c)`.
    In(Box<Expr>, Box<Expr>),
    /// Function call. Args may carry an optional kwarg name
    /// (`no_external_call_to(domain: 'x')`).
    Call(String, Vec<(Option<String>, Expr)>),
}

/// Parse-time errors with byte offset into the source.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    /// Lexer failed before parsing began.
    Lex(LexError),
    /// Expected token kind X but found something else.
    Expected { what: &'static str, found: String, pos: usize },
    /// Token stream ended mid-expression.
    UnexpectedEof { pos: usize },
    /// Caller wrote `foo(a:b, c)` — kwargs and positional args may mix only in
    /// trailing-kwargs form (positional first, kwargs after). We're stricter
    /// to keep evaluation simple.
    PositionalAfterKwarg { pos: usize },
    /// `a in b` where `b` couldn't be parsed as a list.
    InRhsNotList { pos: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Lex(e) => write!(f, "lex error: {e}"),
            ParseError::Expected { what, found, pos } => {
                write!(f, "expected {what} at byte {pos}, found {found}")
            }
            ParseError::UnexpectedEof { pos } => {
                write!(f, "unexpected end of input at byte {pos}")
            }
            ParseError::PositionalAfterKwarg { pos } => write!(
                f,
                "positional argument after keyword argument at byte {pos}"
            ),
            ParseError::InRhsNotList { pos } => {
                write!(f, "right-hand side of `in` must be a list/tuple at byte {pos}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError::Lex(e)
    }
}

/// Parse a full expression string into an [`Expr`].
///
/// The entire input must be consumed — any trailing tokens after a complete
/// expression are reported as `Expected { what: "end of input", ... }`.
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let toks = lex(input)?;
    let mut p = Parser { toks, idx: 0 };
    let e = p.parse_expr()?;
    if !matches!(p.peek(), Token::Eof) {
        let pos = p.toks[p.idx].pos;
        return Err(ParseError::Expected {
            what: "end of input",
            found: format!("{:?}", p.peek()),
            pos,
        });
    }
    Ok(e)
}

/// Internal parser state — index into the token vector + helpers.
struct Parser {
    toks: Vec<TokenWithPos>,
    idx: usize,
}

impl Parser {
    fn peek(&self) -> &Token {
        &self.toks[self.idx].token
    }

    fn pos(&self) -> usize {
        self.toks[self.idx].pos
    }

    fn bump(&mut self) -> TokenWithPos {
        let t = self.toks[self.idx].clone();
        self.idx += 1;
        t
    }

    fn expect(&mut self, want: &Token, what: &'static str) -> Result<(), ParseError> {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(want) {
            self.idx += 1;
            Ok(())
        } else {
            Err(ParseError::Expected {
                what,
                found: format!("{:?}", self.peek()),
                pos: self.pos(),
            })
        }
    }

    // expr := or_expr
    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_or()
    }

    // or_expr := and_expr (("||" | "or") and_expr)*
    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Token::Or) {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Binary(BinOp::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // and_expr := not_expr (("&&" | "and") not_expr)*
    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Token::And) {
            self.bump();
            let right = self.parse_not()?;
            left = Expr::Binary(BinOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // not_expr := ("!" | "not") not_expr | cmp_expr
    fn parse_not(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Token::Not) {
            self.bump();
            let inner = self.parse_not()?;
            return Ok(Expr::Unary(UnaryOp::Not, Box::new(inner)));
        }
        self.parse_cmp()
    }

    // cmp_expr := add_expr ((COMP_OP | "in") add_expr)?
    fn parse_cmp(&mut self) -> Result<Expr, ParseError> {
        let left = self.parse_add()?;
        match self.peek() {
            Token::Op(op) if is_cmp(*op) => {
                let op = *op;
                self.bump();
                let right = self.parse_add()?;
                Ok(Expr::Binary(op, Box::new(left), Box::new(right)))
            }
            Token::In => {
                let in_pos = self.pos();
                self.bump();
                let right = self.parse_add()?;
                // Right side of `in` must be a list literal — either
                // `[a, b]` (already an Expr::List) or a parenthesised tuple
                // `(a, b)` which parse_primary normalises to Expr::List when
                // it sees ≥1 comma.
                if !matches!(right, Expr::List(_)) {
                    return Err(ParseError::InRhsNotList { pos: in_pos });
                }
                Ok(Expr::In(Box::new(left), Box::new(right)))
            }
            _ => Ok(left),
        }
    }

    // add_expr := mul_expr (("+" | "-") mul_expr)*
    fn parse_add(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Op(BinOp::Add) => BinOp::Add,
                Token::Op(BinOp::Sub) => BinOp::Sub,
                _ => break,
            };
            self.bump();
            let right = self.parse_unary()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // unary := "-" unary | primary
    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Token::Op(BinOp::Sub)) {
            self.bump();
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary(UnaryOp::Neg, Box::new(inner)));
        }
        self.parse_primary()
    }

    // primary := NUM | STR | "true" | "false" | "(" expr ("," expr)* ")"
    //          | "[" list "]" | IDENT ( "(" call_args ")" )?
    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let cur = self.toks[self.idx].clone();
        match &cur.token {
            Token::Num(n) => {
                let v = *n;
                self.bump();
                Ok(Expr::Num(v))
            }
            Token::Str(s) => {
                let v = s.clone();
                self.bump();
                Ok(Expr::Str(v))
            }
            Token::True => {
                self.bump();
                Ok(Expr::Bool(true))
            }
            Token::False => {
                self.bump();
                Ok(Expr::Bool(false))
            }
            Token::LParen => {
                self.bump();
                let first = self.parse_expr()?;
                // (expr) | (expr, expr, …) — tuple becomes Expr::List for
                // uniform handling of the `in` right-hand side.
                if matches!(self.peek(), Token::Comma) {
                    let mut items = vec![first];
                    while matches!(self.peek(), Token::Comma) {
                        self.bump();
                        items.push(self.parse_expr()?);
                    }
                    self.expect(&Token::RParen, "')'")?;
                    Ok(Expr::List(items))
                } else {
                    self.expect(&Token::RParen, "')'")?;
                    Ok(first)
                }
            }
            Token::LBracket => {
                self.bump();
                let mut items = Vec::new();
                if !matches!(self.peek(), Token::RBracket) {
                    items.push(self.parse_expr()?);
                    while matches!(self.peek(), Token::Comma) {
                        self.bump();
                        items.push(self.parse_expr()?);
                    }
                }
                self.expect(&Token::RBracket, "']'")?;
                Ok(Expr::List(items))
            }
            Token::Ident(name) => {
                let name = name.clone();
                self.bump();
                if matches!(self.peek(), Token::LParen) {
                    self.bump();
                    let args = self.parse_call_args()?;
                    self.expect(&Token::RParen, "')'")?;
                    Ok(Expr::Call(name, args))
                } else {
                    Ok(Expr::Ident(name))
                }
            }
            Token::Eof => Err(ParseError::UnexpectedEof { pos: cur.pos }),
            other => Err(ParseError::Expected {
                what: "expression",
                found: format!("{other:?}"),
                pos: cur.pos,
            }),
        }
    }

    // call_args := empty | arg ("," arg)*
    // arg       := IDENT ":" expr   (kwarg)
    //            | expr             (positional)
    fn parse_call_args(&mut self) -> Result<Vec<(Option<String>, Expr)>, ParseError> {
        let mut out: Vec<(Option<String>, Expr)> = Vec::new();
        if matches!(self.peek(), Token::RParen) {
            return Ok(out);
        }
        let mut seen_kwarg = false;
        loop {
            // Peek ahead for `IDENT ":"` → kwarg; otherwise positional.
            let (is_kwarg, kw_name) = match (&self.toks[self.idx].token, self.toks.get(self.idx + 1).map(|t| &t.token)) {
                (Token::Ident(n), Some(Token::Colon)) => (true, Some(n.clone())),
                _ => (false, None),
            };
            if is_kwarg {
                seen_kwarg = true;
                self.bump(); // ident
                self.bump(); // colon
                let v = self.parse_expr()?;
                out.push((kw_name, v));
            } else {
                if seen_kwarg {
                    return Err(ParseError::PositionalAfterKwarg { pos: self.pos() });
                }
                let v = self.parse_expr()?;
                out.push((None, v));
            }
            if !matches!(self.peek(), Token::Comma) {
                break;
            }
            self.bump();
        }
        Ok(out)
    }
}

fn is_cmp(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Eq | BinOp::Neq | BinOp::Lt | BinOp::Lte | BinOp::Gt | BinOp::Gte
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(e: Expr) -> Box<Expr> {
        Box::new(e)
    }

    #[test]
    fn parses_number_literal() {
        assert_eq!(parse("42").unwrap(), Expr::Num(42.0));
    }

    #[test]
    fn parses_string_literal() {
        assert_eq!(parse("'EUR'").unwrap(), Expr::Str("EUR".into()));
    }

    #[test]
    fn parses_bool_literals() {
        assert_eq!(parse("true").unwrap(), Expr::Bool(true));
        assert_eq!(parse("false").unwrap(), Expr::Bool(false));
    }

    #[test]
    fn parses_bare_identifier() {
        assert_eq!(parse("spend_total").unwrap(), Expr::Ident("spend_total".into()));
    }

    #[test]
    fn parses_comparison() {
        // spend_total <= max_budget_usd
        assert_eq!(
            parse("spend_total <= max_budget_usd").unwrap(),
            Expr::Binary(
                BinOp::Lte,
                b(Expr::Ident("spend_total".into())),
                b(Expr::Ident("max_budget_usd".into())),
            )
        );
    }

    #[test]
    fn parses_inequality_with_string() {
        assert_eq!(
            parse("data_classification != 'restricted'").unwrap(),
            Expr::Binary(
                BinOp::Neq,
                b(Expr::Ident("data_classification".into())),
                b(Expr::Str("restricted".into())),
            )
        );
    }

    #[test]
    fn parses_in_with_tuple_literal() {
        let e = parse("payment_currency in ('EUR', 'USD')").unwrap();
        let Expr::In(lhs, rhs) = e else {
            panic!("expected In, got {e:?}")
        };
        assert_eq!(*lhs, Expr::Ident("payment_currency".into()));
        assert_eq!(*rhs, Expr::List(vec![Expr::Str("EUR".into()), Expr::Str("USD".into())]));
    }

    #[test]
    fn parses_in_with_bracket_list() {
        let e = parse("x in [1, 2, 3]").unwrap();
        let Expr::In(_, rhs) = e else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Expr::List(vec![Expr::Num(1.0), Expr::Num(2.0), Expr::Num(3.0)])
        );
    }

    #[test]
    fn parses_function_call_with_kwarg() {
        let e = parse("no_external_call_to(domain: 'competitor.com')").unwrap();
        assert_eq!(
            e,
            Expr::Call(
                "no_external_call_to".into(),
                vec![(Some("domain".into()), Expr::Str("competitor.com".into()))]
            )
        );
    }

    #[test]
    fn parses_function_call_positional() {
        let e = parse("len('abc')").unwrap();
        assert_eq!(
            e,
            Expr::Call("len".into(), vec![(None, Expr::Str("abc".into()))])
        );
    }

    #[test]
    fn parses_and_or_precedence() {
        // a && b || c == (a && b) || c
        let e = parse("a && b || c").unwrap();
        assert_eq!(
            e,
            Expr::Binary(
                BinOp::Or,
                b(Expr::Binary(
                    BinOp::And,
                    b(Expr::Ident("a".into())),
                    b(Expr::Ident("b".into()))
                )),
                b(Expr::Ident("c".into())),
            )
        );
    }

    #[test]
    fn parses_keyword_and_or_not() {
        // Lowercase keywords work identically to the symbolic forms.
        let e_kw = parse("a and b or not c").unwrap();
        let e_sym = parse("a && b || !c").unwrap();
        assert_eq!(e_kw, e_sym);
    }

    #[test]
    fn parses_parenthesised_grouping_overrides_precedence() {
        // a && (b || c)
        let e = parse("a && (b || c)").unwrap();
        let Expr::Binary(BinOp::And, _, rhs) = e else {
            panic!()
        };
        assert!(matches!(*rhs, Expr::Binary(BinOp::Or, _, _)));
    }

    #[test]
    fn parses_unary_minus_and_arithmetic() {
        // -1 + 2
        let e = parse("-1 + 2").unwrap();
        assert_eq!(
            e,
            Expr::Binary(
                BinOp::Add,
                b(Expr::Unary(UnaryOp::Neg, b(Expr::Num(1.0)))),
                b(Expr::Num(2.0))
            )
        );
    }

    #[test]
    fn parse_error_carries_position() {
        let err = parse("a == ").unwrap_err();
        match err {
            ParseError::UnexpectedEof { pos } => assert_eq!(pos, 5),
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_unexpected_token() {
        // Trailing junk after a complete expr is rejected.
        let err = parse("a == b c").unwrap_err();
        assert!(matches!(err, ParseError::Expected { .. }));
    }

    #[test]
    fn parses_full_banking_invariant_set() {
        // All three banking invariants must parse.
        assert!(parse("spend_total <= max_budget_usd").is_ok());
        assert!(parse("payment_currency in ('EUR', 'USD')").is_ok());
        assert!(parse("no_external_call_to(domain: 'competitor.com')").is_ok());
    }
}
