//! Server-sent events, read the way an MCP client will (ADR 0049 §5.2).
//!
//! The framing is a parser differential of its own: a client ends a line
//! at LF, CRLF or a lone CR. This reader takes LF and CRLF, and cuts the
//! stream on any other CR, so `: comment\r\rdata: …` can never read as a
//! comment here and as an event in the client. Unknown fields are dropped
//! (a client ignores them anyway); an event is re-emitted with LF line
//! ends and the fields it kept, in their order.

/// Largest event (or line still waiting for its end) the proxy holds.
pub const MAX_EVENT: usize = 4 * 1024 * 1024;

/// The stream cannot be read as events the client would read the same
/// way, or an event is over [`MAX_EVENT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Broken;

/// One field line of an event, as the client reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// `:…`, a comment (its text after the colon).
    Comment(String),
    /// `data`.
    Data(String),
    /// `id`.
    Id(String),
    /// `event`.
    Event(String),
    /// `retry`.
    Retry(String),
}

/// An event: its fields in the order received.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    /// The fields.
    pub fields: Vec<Field>,
}

impl Event {
    /// The event's data, as the client joins it (`None` without a `data`
    /// field).
    pub fn data(&self) -> Option<String> {
        let mut out: Option<String> = None;
        for f in &self.fields {
            if let Field::Data(d) = f {
                match &mut out {
                    Some(o) => {
                        o.push('\n');
                        o.push_str(d);
                    }
                    None => out = Some(d.clone()),
                }
            }
        }
        out
    }

    /// The event's last `id`, if any.
    pub fn id(&self) -> Option<&str> {
        self.fields.iter().rev().find_map(|f| match f {
            Field::Id(id) => Some(id.as_str()),
            _ => None,
        })
    }

    /// The event as bytes, ending with its blank line.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in &self.fields {
            let (name, value) = match f {
                Field::Comment(c) => {
                    out.push(b':');
                    out.extend_from_slice(c.as_bytes());
                    out.push(b'\n');
                    continue;
                }
                // Data with line ends (whitespace a filtered JSON kept)
                // goes as several data lines, which the client joins back.
                Field::Data(v) => {
                    for line in v.split('\n') {
                        out.extend_from_slice(b"data: ");
                        out.extend_from_slice(line.as_bytes());
                        out.push(b'\n');
                    }
                    continue;
                }
                Field::Id(v) => ("id", v),
                Field::Event(v) => ("event", v),
                Field::Retry(v) => ("retry", v),
            };
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.push(b'\n');
        }
        out.push(b'\n');
        out
    }

    /// The same event with `data` replaced by `data` (one line: JSON
    /// without line ends), its other fields kept in place.
    pub fn with_data(&self, data: String) -> Self {
        let mut fields = Vec::new();
        let mut placed = false;
        for f in &self.fields {
            match f {
                Field::Data(_) if placed => {}
                Field::Data(_) => {
                    fields.push(Field::Data(data.clone()));
                    placed = true;
                }
                other => fields.push(other.clone()),
            }
        }
        Self { fields }
    }

    /// Only its `id` (and `retry`): what is left of a dropped event, so the
    /// client's last event ID still moves and a resumption stays exact.
    pub fn without_data(&self) -> Option<Self> {
        let fields: Vec<Field> = self
            .fields
            .iter()
            .filter(|f| matches!(f, Field::Id(_) | Field::Retry(_)))
            .cloned()
            .collect();
        (!fields.is_empty()).then_some(Self { fields })
    }
}

/// Reads events from the bytes of a stream as they come.
#[derive(Debug, Default)]
pub struct Reader {
    line: Vec<u8>,
    event: Event,
    size: usize,
}

impl Reader {
    /// The events `bytes` completes.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Event>, Broken> {
        let mut out = Vec::new();
        for &b in bytes {
            if b != b'\n' {
                self.line.push(b);
                if self.line.len() > MAX_EVENT {
                    return Err(Broken);
                }
                continue;
            }
            let mut line = std::mem::take(&mut self.line);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.contains(&b'\r') {
                return Err(Broken);
            }
            if line.is_empty() {
                if !self.event.fields.is_empty() {
                    out.push(std::mem::take(&mut self.event));
                }
                self.size = 0;
                continue;
            }
            self.size += line.len();
            if self.size > MAX_EVENT {
                return Err(Broken);
            }
            let line = String::from_utf8(line).map_err(|_| Broken)?;
            if let Some(comment) = line.strip_prefix(':') {
                self.event.fields.push(Field::Comment(comment.to_owned()));
                continue;
            }
            let (name, value) = match line.split_once(':') {
                Some((n, v)) => (n, v.strip_prefix(' ').unwrap_or(v)),
                None => (line.as_str(), ""),
            };
            let value = value.to_owned();
            match name {
                "data" => self.event.fields.push(Field::Data(value)),
                "id" => self.event.fields.push(Field::Id(value)),
                "event" => self.event.fields.push(Field::Event(value)),
                "retry" => self.event.fields.push(Field::Retry(value)),
                _ => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_split_on_lf_and_crlf_and_a_lone_cr_breaks_the_stream() {
        let mut r = Reader::default();
        let events = r
            .push(b"id: 1\r\ndata: {\"a\":1}\r\n\r\n: keep\n\nretry: 10")
            .expect("events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id(), Some("1"));
        assert_eq!(events[0].data().as_deref(), Some("{\"a\":1}"));
        assert_eq!(events[1].fields, vec![Field::Comment(" keep".into())]);
        let events = r.push(b"\n\n").expect("events");
        assert_eq!(events[0].fields, vec![Field::Retry("10".into())]);
        // `\r\r` would end two lines in a client: here the stream breaks.
        let mut r = Reader::default();
        assert_eq!(
            r.push(b": comment\r\rdata: {\"method\":\"sampling/createMessage\"}\n\n"),
            Err(Broken)
        );
        let mut r = Reader::default();
        assert_eq!(r.push(b"data: a\rb\n\n"), Err(Broken));
    }

    #[test]
    fn data_lines_join_and_unknown_fields_are_dropped() {
        let mut r = Reader::default();
        let e = r
            .push(b"event: message\ndata:x\ndata: y\nweird: z\nid\n\n")
            .expect("events")
            .remove(0);
        assert_eq!(e.data().as_deref(), Some("x\ny"));
        assert_eq!(e.id(), Some(""));
        assert_eq!(e.to_bytes(), b"event: message\ndata: x\ndata: y\nid: \n\n");
        assert_eq!(
            e.with_data("{}".into()).to_bytes(),
            b"event: message\ndata: {}\nid: \n\n"
        );
        assert_eq!(e.without_data().unwrap().to_bytes(), b"id: \n\n");
        // The priming event: an id and an empty data.
        let p = r.push(b"id: 0\ndata:\n\n").expect("events").remove(0);
        assert_eq!(p.data().as_deref(), Some(""));
    }

    #[test]
    fn an_event_over_the_cap_breaks_the_stream() {
        let mut r = Reader::default();
        let line = vec![b'a'; 1024 * 1024];
        let mut out = Ok(Vec::new());
        for _ in 0..5 {
            out = r
                .push(b"data: ")
                .and_then(|_| r.push(&line))
                .and_then(|_| r.push(b"\n"));
            if out.is_err() {
                break;
            }
        }
        assert_eq!(out, Err(Broken));
    }
}
