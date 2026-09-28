//! How the daemon writes its log: text for a terminal, or JSON Lines for a collector.
//! [`crate::env::LOG_FORMAT`] chooses.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// The log's format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Text,
    /// One JSON object per line, each field a key, the message under `message`.
    Json,
}

impl Format {
    /// `text` or `json`. `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// The daemon's subscriber: events `filter` passes, in `format`, to `writer`.
pub fn subscriber<W>(
    filter: EnvFilter,
    format: Format,
    writer: W,
) -> Box<dyn tracing::Subscriber + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(writer);
    match format {
        Format::Text => Box::new(builder.finish()),
        Format::Json => Box::new(
            builder
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .with_span_list(false)
                .finish(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// What `format` writes for one event with two fields.
    fn written(format: Format) -> String {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = buf.clone();
        let writer = move || Sink(sink.clone());
        let subscriber = subscriber(EnvFilter::new("info"), format, writer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(path = "/lodash", status = 403_u16, "refused by policy");
            tracing::debug!("filtered out");
        });
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn json_is_one_object_per_line_with_each_field_a_key() {
        let written = written(Format::Json);
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 1, "the debug line is filtered: {written}");
        let event: serde_json::Value = serde_json::from_str(lines[0]).expect("one JSON object");
        assert_eq!(event["level"], "INFO");
        assert_eq!(event["message"], "refused by policy");
        assert_eq!(event["path"], "/lodash");
        assert_eq!(event["status"], 403);
        assert!(event["timestamp"].is_string(), "{event}");
        assert!(event.get("target").is_none(), "{event}");
    }

    /// `text` without its ANSI colour codes, which text output keeps.
    fn plain(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                chars.by_ref().find(|c| *c == 'm');
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn text_is_the_message_then_the_fields() {
        let written = plain(&written(Format::Text));
        assert_eq!(written.lines().count(), 1, "{written}");
        assert!(
            written.contains("refused by policy path=\"/lodash\" status=403"),
            "{written}"
        );
    }

    #[test]
    fn a_format_is_text_or_json() {
        assert_eq!(Format::parse("text"), Some(Format::Text));
        assert_eq!(Format::parse("json"), Some(Format::Json));
        assert_eq!(Format::parse("logfmt"), None);
        assert_eq!(Format::default(), Format::Text);
    }
}
