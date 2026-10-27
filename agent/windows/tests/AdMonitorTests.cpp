// Active Directory monitoring: event XML parsing and which Security events leave a domain controller.
#include <cstdio>
#include <string>

#include "AdEventRules.h"

using namespace antivirus::agent::admonitor;

static int failures = 0;
#define CHECK(cond)                                              \
  do {                                                           \
    if (!(cond)) {                                               \
      std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
      ++failures;                                                \
    }                                                            \
  } while (0)

static std::wstring Xml(int id, const std::wstring& data) {
  return L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
         L"<EventID>" + std::to_wstring(id) + L"</EventID><TimeCreated SystemTime=\"2026-10-27T10:00:00.000Z\"/>"
         L"<EventRecordID>9001</EventRecordID><Computer>DC01.corp.example</Computer></System><EventData>" + data +
         L"</EventData></Event>";
}

static std::wstring D(const std::wstring& name, const std::wstring& value) {
  return L"<Data Name=\"" + name + L"\">" + value + L"</Data>";
}

int main() {
  // Parsing: fields, entities, empty elements.
  const auto parsed = ParseEventXml(Xml(4728, D(L"MemberName", L"CN=Jo &amp; Co,OU=Staff,DC=corp,DC=example") +
                                                  D(L"TargetUserName", L"Domain Admins") + D(L"TargetSid", L"S-1-5-21-1-2-3-512") +
                                                  D(L"SubjectUserName", L"admin.bob") + L"<Data Name=\"PrivilegeList\"/>"));
  CHECK(parsed.has_value());
  CHECK(parsed->eventId == 4728 && parsed->recordId == 9001 && parsed->computer == L"DC01.corp.example");
  CHECK(parsed->data.at(L"MemberName") == L"CN=Jo & Co,OU=Staff,DC=corp,DC=example");
  CHECK(parsed->data.count(L"PrivilegeList") == 1 && parsed->data.at(L"PrivilegeList").empty());
  const auto added = Classify(*parsed);
  CHECK(added.eventType == L"ad.group.member_added");
  CHECK(added.extraJson.find(L"\"privilegedGroup\":\"Domain Admins\"") != std::wstring::npos);
  CHECK(added.summary == L"Jo & Co was added to Domain Admins by admin.bob");

  // Ordinary group: no privileged flag.
  const auto ordinary = Classify(*ParseEventXml(Xml(4756, D(L"MemberName", L"CN=Jo") + D(L"TargetUserName", L"Finance") +
                                                             D(L"TargetSid", L"S-1-5-21-1-2-3-1145"))));
  CHECK(ordinary.eventType == L"ad.group.member_added" && ordinary.extraJson.find(L"privilegedGroup") == std::wstring::npos);
  CHECK(PrivilegedGroupName(L"S-1-5-32-544") == L"Administrators");
  CHECK(PrivilegedGroupName(L"S-1-5-21-9-9-9-519") == L"Enterprise Admins");
  CHECK(PrivilegedGroupName(L"S-1-5-21-9-9-9-1519").empty());

  // Kerberoasting: RC4 tickets for user services only.
  const auto rc4 = [](const std::wstring& service, const std::wstring& type) {
    return Classify(*ParseEventXml(Xml(4769, D(L"ServiceName", service) + D(L"TicketEncryptionType", type) + D(L"Status", L"0x0") +
                                                 D(L"TargetUserName", L"eve@CORP.EXAMPLE"))));
  };
  CHECK(rc4(L"svc_sql", L"0x17").eventType == L"ad.kerberos.rc4_service_ticket");
  CHECK(rc4(L"svc_sql", L"0x12").eventType.empty());   // AES: normal
  CHECK(rc4(L"FILESRV01$", L"0x17").eventType.empty()); // machine account service
  CHECK(rc4(L"krbtgt", L"0x17").eventType.empty());

  // AS-REP roasting: TGT issued without pre-authentication.
  CHECK(Classify(*ParseEventXml(Xml(4768, D(L"TargetUserName", L"legacy") + D(L"Status", L"0x0") + D(L"PreAuthType", L"0"))))
            .eventType == L"ad.kerberos.asrep");
  CHECK(Classify(*ParseEventXml(Xml(4768, D(L"TargetUserName", L"jo") + D(L"Status", L"0x0") + D(L"PreAuthType", L"2"))))
            .eventType.empty());

  // DCSync: replication rights used by a user, not a DC; Entra Connect is labelled.
  const auto dcsync = [](const std::wstring& subject) {
    return Classify(*ParseEventXml(Xml(4662, D(L"SubjectUserName", subject) +
                                                 D(L"Properties", L"%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}"))));
  };
  CHECK(dcsync(L"mallory").eventType == L"ad.replication.requested");
  CHECK(dcsync(L"mallory").extraJson == L"\"knownSyncAccount\":false");
  CHECK(dcsync(L"DC02$").eventType.empty());
  CHECK(dcsync(L"MSOL_1a2b3c").extraJson == L"\"knownSyncAccount\":true");
  CHECK(Classify(*ParseEventXml(Xml(4662, D(L"SubjectUserName", L"bob") + D(L"Properties", L"%%7684 {bf967a86-0de6-11d0-a285-00aa003049e2}"))))
            .eventType.empty());

  // Directory changes: AdminSDHolder and sensitive attributes, not every attribute.
  CHECK(Classify(*ParseEventXml(Xml(5136, D(L"ObjectDN", L"CN=AdminSDHolder,CN=System,DC=corp,DC=example") + D(L"ObjectClass", L"container") +
                                              D(L"AttributeLDAPDisplayName", L"nTSecurityDescriptor"))))
            .eventType == L"ad.adminsdholder.modified");
  CHECK(Classify(*ParseEventXml(Xml(5136, D(L"ObjectDN", L"CN=FS01,OU=Servers,DC=corp,DC=example") + D(L"ObjectClass", L"computer") +
                                              D(L"AttributeLDAPDisplayName", L"msDS-AllowedToActOnBehalfOfOtherIdentity"))))
            .eventType == L"ad.object.sensitive_change");
  CHECK(Classify(*ParseEventXml(Xml(5136, D(L"ObjectDN", L"CN=Jo,OU=Staff,DC=corp,DC=example") + D(L"ObjectClass", L"user") +
                                              D(L"AttributeLDAPDisplayName", L"telephoneNumber"))))
            .eventType.empty());

  // Routine computer password changes stay on the DC.
  CHECK(Classify(*ParseEventXml(Xml(4742, D(L"TargetUserName", L"PC01$") + D(L"AllowedToDelegateTo", L"-") + D(L"UserAccountControl", L"-"))))
            .eventType.empty());
  CHECK(Classify(*ParseEventXml(Xml(4724, D(L"TargetUserName", L"krbtgt")))).extraJson == L"\"krbtgt\":true");
  CHECK(Classify(*ParseEventXml(Xml(4625, D(L"TargetUserName", L"jo")))).eventType.empty());  // handled by brute-force guard

  if (failures == 0) std::printf("admonitor tests passed\n");
  return failures == 0 ? 0 : 1;
}
