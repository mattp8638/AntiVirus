from datetime import date, datetime

import pytest

from fenrir_cloud import db as database, psa, regional


@pytest.mark.parametrize("year, sunday", [(2024, date(2024, 3, 31)), (2025, date(2025, 4, 20)), (2026, date(2026, 4, 5)),
                                          (2027, date(2027, 3, 28)), (2038, date(2038, 4, 25))])
def test_easter(year, sunday):
    assert regional.easter(year) == sunday


def _days(calendar, year):
    return sorted(d.isoformat() for d in regional.calendar_days(calendar, year))


def test_published_calendars():
    # gov.uk: substitute days when Christmas and Boxing Day fall at the weekend.
    assert _days("GB-ENG", 2027) == ["2027-01-01", "2027-03-26", "2027-03-29", "2027-05-03", "2027-05-31", "2027-08-30",
                                     "2027-12-27", "2027-12-28"]
    assert _days("GB-SCT", 2027) == ["2027-01-01", "2027-01-04", "2027-03-26", "2027-05-03", "2027-05-31", "2027-08-02",
                                     "2027-11-30", "2027-12-27", "2027-12-28"]
    assert "2026-07-13" in _days("GB-NIR", 2026)  # the Twelfth on a Sunday moves to Monday
    # Ireland: St Brigid's Day is the first Monday in February (1 February when that is a Friday).
    assert _days("IE", 2026)[:3] == ["2026-01-01", "2026-02-02", "2026-03-17"]
    # US federal, observed: Saturday holidays move to Friday, so New Year 2028 is observed on 31 December 2027.
    us = _days("US", 2027)
    assert {"2027-06-18", "2027-07-05", "2027-12-24", "2027-12-31", "2027-11-25"} <= set(us) and len(us) == 12
    assert _days("none", 2027) == []


def test_business_hours_skip_holidays():
    london = {"days": [0, 1, 2, 3, 4], "start": 9, "end": 17, "tz": "Europe/London"}
    christmas_eve = datetime(2026, 12, 24, 16, 0)  # Thursday, 16:00 in London (UTC in winter)
    assert psa.add_business_hours(christmas_eve, 4, london) == datetime(2026, 12, 25, 12, 0)
    holidays = sorted(regional.holiday_dates({"holidayCalendar": "GB-ENG", "extraHolidays": []}, range(2026, 2028)))
    # 25 Dec (Fri) and 28 Dec (Boxing Day substitute) are holidays, 26-27 the weekend: the clock resumes on the 29th.
    assert psa.add_business_hours(christmas_eve, 4, {**london, "holidays": holidays}) == datetime(2026, 12, 29, 12, 0)


def test_region_settings_drive_currency_time_zone_and_sla_holidays(client, admin, tenant):
    region = client.get("/api/console/region", headers=admin).json()
    assert region["currency"] == "GBP" and region["holidayCalendar"] == "none" and "US" in region["calendars"]
    assert client.put("/api/console/region", headers=admin, json={"currency": "usd", "timeZone": "Mars/Olympus"}).status_code == 400
    assert client.put("/api/console/region", headers=admin, json={"extraHolidays": ["2026-02-30"]}).status_code == 400
    saved = client.put("/api/console/region", headers=admin, json={"currency": "usd", "timeZone": "America/New_York",
                                                                    "holidayCalendar": "US", "extraHolidays": ["2026-12-24"]}).json()
    assert saved["currency"] == "USD" and saved["timeZone"] == "America/New_York" and saved["upcomingHolidays"]

    contract = client.post("/api/console/billing/contracts", headers=admin, json={
        "accountTenantId": tenant["id"], "name": "Managed", "sla": {"P3": 4, "respond": {"P3": 1}},
        "businessHours": {"days": [0, 1, 2, 3, 4], "start": 9, "end": 17}}).json()
    assert contract["currency"] == "USD"  # the MSP's default when the agreement does not name one
    ticket = client.post("/api/console/tickets", headers=admin, json={"accountTenantId": tenant["id"], "subject": "Printer"}).json()
    from fenrir_cloud.models import Ticket

    with database.session_factory()() as db:
        row = db.get(Ticket, ticket["id"])
        row.priority, row.agreement_id = "P3", contract["id"]
        row.created_at = datetime(2026, 12, 23, 20, 0)  # Wednesday 15:00 in New York
        psa.apply_sla(db, row)
        # 2 hours on the 23rd; the 24th (extra holiday) and 25th (Christmas) are skipped; 2 hours on Monday the 28th.
        assert row.sla_due_at == datetime(2026, 12, 28, 16, 0)  # 11:00 in New York
