//! Dates for `klav log`: UTC only, no time-zone database.

use std::time::{SystemTime, UNIX_EPOCH};

const DAY_MS: i64 = 86_400_000;

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// `20261102T143005.123Z`: sorts by time as text, for file names.
pub(crate) fn file_stamp(ms: i64) -> String {
    let days = ms.div_euclid(DAY_MS);
    let rest = ms.rem_euclid(DAY_MS);
    let (y, m, d) = civil_from_days(days);
    let secs = rest / 1000;
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}.{:03}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        rest % 1000
    )
}

/// `2026-11-02 14:30:05Z`.
pub(crate) fn format_utc(ms: i64) -> String {
    let days = ms.div_euclid(DAY_MS);
    let rest = ms.rem_euclid(DAY_MS) / 1000;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// `2026-11-14 18:03` (UTC, to the minute).
pub(crate) fn format_utc_minutes(ms: i64) -> String {
    let days = ms.div_euclid(DAY_MS);
    let rest = ms.rem_euclid(DAY_MS) / 1000;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rest / 3600,
        rest / 60 % 60
    )
}

fn number(text: &str, min: i64, max: i64) -> Option<i64> {
    let n: i64 = text.parse().ok()?;
    (min..=max).contains(&n).then_some(n)
}

/// A duration back from now (`24h`), `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM[:SS]`
/// (UTC; a trailing `Z` is accepted). With `end_of_day`, a bare date means
/// its last millisecond.
pub(crate) fn parse_when(text: &str, end_of_day: bool) -> Result<i64, String> {
    let text = text.trim();
    if text.chars().next().is_some_and(|c| c.is_ascii_digit()) && !text.contains('-') {
        let d = crate::cli::parse_duration(text)?;
        return Ok(now_ms() - i64::try_from(d.as_millis()).unwrap_or(i64::MAX / 2));
    }
    let bad = || format!("invalid time {text:?} (try 24h, 2026-11-02 or 2026-11-02T14:30)");
    let text = text.trim_end_matches(['Z', 'z']);
    let (date, time) = match text.split_once(['T', 't', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (text, None),
    };
    let mut parts = date.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let (y, m, d) = (
        number(y, 1970, 9999).ok_or_else(bad)?,
        number(m, 1, 12).ok_or_else(bad)?,
        number(d, 1, 31).ok_or_else(bad)?,
    );
    let day = days_from_civil(y, m, d) * DAY_MS;
    let Some(time) = time else {
        return Ok(if end_of_day { day + DAY_MS - 1 } else { day });
    };
    let mut parts = time.split(':');
    let h = parts
        .next()
        .and_then(|t| number(t, 0, 23))
        .ok_or_else(bad)?;
    let min = parts
        .next()
        .and_then(|t| number(t, 0, 59))
        .ok_or_else(bad)?;
    let s = match parts.next() {
        Some(t) => number(t, 0, 59).ok_or_else(bad)?,
        None => 0,
    };
    if parts.next().is_some() {
        return Err(bad());
    }
    Ok(day + ((h * 60 + min) * 60 + s) * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        let ms = parse_when("2026-11-02T14:30:05Z", false).unwrap();
        assert_eq!(format_utc(ms), "2026-11-02 14:30:05Z");
        assert_eq!(parse_when("1970-01-01", false).unwrap(), 0);
        assert_eq!(parse_when("1970-01-01", true).unwrap(), DAY_MS - 1);
        assert_eq!(
            format_utc(parse_when("2024-02-29", false).unwrap()),
            "2024-02-29 00:00:00Z"
        );
        let ago = parse_when("1h", false).unwrap();
        assert!((now_ms() - ago - 3_600_000).abs() < 5_000);
        assert!(parse_when("2026-13-01", false).is_err());
        assert!(parse_when("yesterday", false).is_err());
    }
}
