//! RFC 3339 UTC timestamps without a date/time dependency.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Days since 1970-01-01 to (year, month, day); proleptic Gregorian.
/// Algorithm from Howard Hinnant's public-domain "date algorithms".
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) to days since 1970-01-01; inverse of `civil_from_days`.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// ISO 8601 (year, week) of a day number. Weeks start on Monday; week 1
/// contains the year's first Thursday.
pub fn iso_week(days: i64) -> (i64, u32) {
    let weekday = (days + 3).rem_euclid(7); // Monday = 0
    let thursday = days - weekday + 3;
    let (y, _, _) = civil_from_days(thursday);
    let week = (thursday - days_from_civil(y, 1, 1)) / 7 + 1;
    (y, week as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip_and_iso_weeks() {
        for d in [-1000i64, 0, 365, 11_016, 20_000, 20_777] {
            let (y, m, dd) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, dd), d);
        }
        // 2021-01-03 is Sunday of ISO week 2020-W53; 2021-01-04 is 2021-W01.
        assert_eq!(iso_week(days_from_civil(2021, 1, 3)), (2020, 53));
        assert_eq!(iso_week(days_from_civil(2021, 1, 4)), (2021, 1));
        // 2026-11-20 is a Friday in week 47.
        assert_eq!(iso_week(days_from_civil(2026, 11, 20)), (2026, 47));
        // 2024-12-30 (Monday) belongs to 2025-W01.
        assert_eq!(iso_week(days_from_civil(2024, 12, 30)), (2025, 1));
    }

    #[test]
    fn known_dates() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_795_000_000), "2026-11-18T11:06:40Z");
        assert_eq!(rfc3339_utc(-1), "1969-12-31T23:59:59Z");
    }
}
