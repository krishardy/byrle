//! How the daemon writes its log: text for a terminal, or JSON Lines for a collector.
//! [`crate::env::LOG_FORMAT`] chooses.

use tracing::field::{Field, Visit};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::registry::LookupSpan;

/// The log's format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Text,
    /// One JSON object per line, as an OpenTelemetry log record.
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
        Format::Json => Box::new(builder.event_format(OtelRecord).finish()),
    }
}

/// Formats an event as an OpenTelemetry log record.
struct OtelRecord;

impl<S, N> FormatEvent<S, N> for OtelRecord
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let level = event.metadata().level();
        let record = serde_json::json!({
            "timestamp": jiff::Timestamp::now().to_string(),
            "severity_text": level.as_str(),
            "severity_number": severity_number(level),
            "body": fields.body,
            "attributes": fields.attributes,
        });
        writeln!(writer, "{record}")
    }
}

/// OpenTelemetry's `SeverityNumber` for a level: the first number of its range.
fn severity_number(level: &tracing::Level) -> u8 {
    match *level {
        tracing::Level::TRACE => 1,
        tracing::Level::DEBUG => 5,
        tracing::Level::INFO => 9,
        tracing::Level::WARN => 13,
        tracing::Level::ERROR => 17,
    }
}

/// An event's message, as the record's body, and its other fields, as attributes.
#[derive(Default)]
struct Fields {
    body: serde_json::Value,
    attributes: serde_json::Map<String, serde_json::Value>,
}

impl Fields {
    fn put(&mut self, field: &Field, value: serde_json::Value) {
        if field.name() == "message" {
            self.body = value;
        } else {
            self.attributes.insert(field.name().to_owned(), value);
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, value.into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, format!("{value:?}").into());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
            tracing::info!(
                url.path = "/lodash",
                http.response.status_code = 403_u16,
                "refused by policy"
            );
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
    fn json_is_an_opentelemetry_log_record_per_line() {
        let written = written(Format::Json);
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 1, "the debug line is filtered: {written}");
        let record: serde_json::Value = serde_json::from_str(lines[0]).expect("one JSON object");
        assert_eq!(record["severity_text"], "INFO");
        assert_eq!(record["severity_number"], 9);
        assert_eq!(record["body"], "refused by policy");
        assert_eq!(
            record["attributes"],
            serde_json::json!({"url.path": "/lodash", "http.response.status_code": 403})
        );
        let at = record["timestamp"].as_str().expect("a timestamp");
        assert!(at.parse::<jiff::Timestamp>().is_ok(), "{at}");
        let keys: Vec<&String> = record.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "attributes",
                "body",
                "severity_number",
                "severity_text",
                "timestamp"
            ]
        );
    }

    /// Each level's number starts its OpenTelemetry range, and a value that is not text or a
    /// number is written as its debug form.
    #[test]
    fn severity_numbers_and_debug_values() {
        let numbers: Vec<u8> = [
            tracing::Level::TRACE,
            tracing::Level::DEBUG,
            tracing::Level::INFO,
            tracing::Level::WARN,
            tracing::Level::ERROR,
        ]
        .iter()
        .map(severity_number)
        .collect();
        assert_eq!(numbers, [1, 5, 9, 13, 17]);

        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = buf.clone();
        let subscriber = subscriber(EnvFilter::new("warn"), Format::Json, move || {
            Sink(sink.clone())
        });
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                byrle.package.versions = ?["1.0.0"],
                byrle.analysis.completed = true,
                byrle.duration_ms = -1_i64,
                byrle.ratio = 0.5,
                "every kind"
            );
        });
        let written = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let record: serde_json::Value = serde_json::from_str(written.trim()).unwrap();
        assert_eq!(record["severity_number"], 13);
        assert_eq!(
            record["attributes"],
            serde_json::json!({
                "byrle.package.versions": "[\"1.0.0\"]",
                "byrle.analysis.completed": true,
                "byrle.duration_ms": -1,
                "byrle.ratio": 0.5,
            })
        );
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
            written
                .contains("refused by policy url.path=\"/lodash\" http.response.status_code=403"),
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
