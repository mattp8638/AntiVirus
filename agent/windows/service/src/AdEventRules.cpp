#include "AdEventRules.h"

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <vector>

namespace antivirus::agent {

namespace admonitor {
namespace {

std::wstring J(const std::wstring& value) {
  std::wstring out = L"\"";
  for (const auto c : value) {
    switch (c) {
      case L'"': out += L"\\\""; break;
      case L'\\': out += L"\\\\"; break;
      case L'\n': out += L"\\n"; break;
      case L'\r': out += L"\\r"; break;
      case L'\t': out += L"\\t"; break;
      default:
        if (c < 0x20) {
          wchar_t buffer[8];
          swprintf(buffer, 8, L"\\u%04x", static_cast<unsigned>(c));
          out += buffer;
        } else {
          out += c;
        }
    }
  }
  return out + L"\"";
}

std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return value;
}

bool EndsWith(const std::wstring& value, const std::wstring& suffix) {
  return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::wstring Unescape(const std::wstring& text) {
  std::wstring out;
  out.reserve(text.size());
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] != L'&') {
      out += text[i];
      continue;
    }
    const auto end = text.find(L';', i);
    if (end == std::wstring::npos || end - i > 8) {
      out += text[i];
      continue;
    }
    const auto entity = text.substr(i + 1, end - i - 1);
    if (entity == L"amp") out += L'&';
    else if (entity == L"lt") out += L'<';
    else if (entity == L"gt") out += L'>';
    else if (entity == L"quot") out += L'"';
    else if (entity == L"apos") out += L'\'';
    else if (!entity.empty() && entity[0] == L'#') {
      const bool hex = entity.size() > 1 && (entity[1] == L'x' || entity[1] == L'X');
      out += static_cast<wchar_t>(std::wcstoul(entity.c_str() + (hex ? 2 : 1), nullptr, hex ? 16 : 10));
    } else {
      out += text.substr(i, end - i + 1);
    }
    i = end;
  }
  return out;
}

// Text between <tag ...> and </tag>, from position `from`.
std::wstring Element(const std::wstring& xml, const std::wstring& tag, std::size_t from = 0) {
  const auto open = xml.find(L"<" + tag, from);
  if (open == std::wstring::npos) return {};
  const auto close = xml.find(L'>', open);
  if (close == std::wstring::npos || xml[close - 1] == L'/') return {};
  const auto end = xml.find(L"</" + tag + L">", close);
  return end == std::wstring::npos ? std::wstring() : Unescape(xml.substr(close + 1, end - close - 1));
}

std::wstring Attribute(const std::wstring& xml, const std::wstring& tag, const std::wstring& attribute) {
  const auto open = xml.find(L"<" + tag);
  if (open == std::wstring::npos) return {};
  const auto close = xml.find(L'>', open);
  const auto at = xml.find(attribute + L"=", open);
  if (at == std::wstring::npos || at > close) return {};
  const auto quote = xml[at + attribute.size() + 1];
  const auto start = at + attribute.size() + 2;
  const auto end = xml.find(quote, start);
  return end == std::wstring::npos ? std::wstring() : Unescape(xml.substr(start, end - start));
}

bool Filled(const std::wstring& value) { return !value.empty() && value != L"-"; }

const std::wstring& Field(const SecurityEvent& event, const wchar_t* name) {
  static const std::wstring empty;
  const auto it = event.data.find(name);
  return it == event.data.end() ? empty : it->second;
}

bool MachineAccount(const std::wstring& name) { return EndsWith(name, L"$"); }

}  // namespace

std::optional<SecurityEvent> ParseEventXml(const std::wstring& xml) {
  SecurityEvent event;
  const auto id = Element(xml, L"EventID");
  if (id.empty()) return std::nullopt;
  event.eventId = std::wcstoul(id.c_str(), nullptr, 10);
  event.recordId = std::wcstoull(Element(xml, L"EventRecordID").c_str(), nullptr, 10);
  event.timeCreated = Attribute(xml, L"TimeCreated", L"SystemTime");
  event.computer = Element(xml, L"Computer");
  // <Data Name='X'>value</Data> (Windows renders double quotes; accept both). Security events carry up to ~30.
  std::size_t position = 0;
  int fields = 0;
  while ((position = xml.find(L"<Data Name=", position)) != std::wstring::npos && fields < 60) {
    const auto quote = xml[position + 11];
    const auto nameStart = position + 12;
    const auto nameEnd = xml.find(quote, nameStart);
    if (nameEnd == std::wstring::npos) break;
    const auto name = xml.substr(nameStart, nameEnd - nameStart);
    const auto tagEnd = xml.find(L'>', nameEnd);
    if (tagEnd == std::wstring::npos) break;
    std::wstring value;
    if (xml[tagEnd - 1] != L'/') {
      const auto valueEnd = xml.find(L"</Data>", tagEnd);
      if (valueEnd == std::wstring::npos) break;
      value = Unescape(xml.substr(tagEnd + 1, valueEnd - tagEnd - 1));
      position = valueEnd;
    } else {
      position = tagEnd;
    }
    if (value.size() > 1024) value.resize(1024);
    event.data[name] = value;
    ++fields;
  }
  return event;
}

std::wstring PrivilegedGroupName(const std::wstring& sid) {
  static const std::map<std::wstring, std::wstring> builtin = {
      {L"S-1-5-32-544", L"Administrators"},   {L"S-1-5-32-548", L"Account Operators"}, {L"S-1-5-32-549", L"Server Operators"},
      {L"S-1-5-32-550", L"Print Operators"},  {L"S-1-5-32-551", L"Backup Operators"},
  };
  if (const auto it = builtin.find(sid); it != builtin.end()) return it->second;
  if (sid.rfind(L"S-1-5-21-", 0) != 0) return {};
  const auto dash = sid.rfind(L'-');
  const auto rid = sid.substr(dash + 1);
  static const std::map<std::wstring, std::wstring> domain = {
      {L"512", L"Domain Admins"}, {L"516", L"Domain Controllers"},           {L"518", L"Schema Admins"},  {L"519", L"Enterprise Admins"},
      {L"520", L"Group Policy Creator Owners"}, {L"526", L"Key Admins"}, {L"527", L"Enterprise Key Admins"},
  };
  const auto it = domain.find(rid);
  return it == domain.end() ? std::wstring() : it->second;
}

Classified Classify(const SecurityEvent& event) {
  const auto& subject = Field(event, L"SubjectUserName");
  const auto& target = Field(event, L"TargetUserName");
  const auto by = Filled(subject) ? L" by " + subject : std::wstring();
  switch (event.eventId) {
    case 4720: return {L"ad.user.created", L"User " + target + L" was created" + by, {}};
    case 4722: return {L"ad.user.enabled", L"User " + target + L" was enabled" + by, {}};
    case 4725: return {L"ad.user.disabled", L"User " + target + L" was disabled" + by, {}};
    case 4726: return {L"ad.user.deleted", L"User " + target + L" was deleted" + by, {}};
    case 4738: return {L"ad.user.changed", L"User " + target + L" was changed" + by, {}};
    case 4740: return {L"ad.user.locked_out", L"User " + target + L" was locked out (caller " + Field(event, L"TargetDomainName") + L")", {}};
    case 4767: return {L"ad.user.unlocked", L"User " + target + L" was unlocked" + by, {}};
    case 4724: {
      const bool krbtgt = Lower(target) == L"krbtgt";
      return {L"ad.user.password_reset", (krbtgt ? L"The krbtgt password was reset" : L"Password of " + target + L" was reset") + by,
              krbtgt ? L"\"krbtgt\":true" : L""};
    }
    case 4741: return {L"ad.computer.created", L"Computer " + target + L" was added to the domain" + by, {}};
    case 4743: return {L"ad.computer.deleted", L"Computer " + target + L" was removed from the domain" + by, {}};
    case 4742: {
      // Joins and password changes rewrite computer objects constantly; only delegation and UAC changes matter.
      if (!Filled(Field(event, L"AllowedToDelegateTo")) && !Filled(Field(event, L"UserAccountControl"))) return {};
      return {L"ad.computer.changed", L"Computer " + target + L" delegation or account settings changed" + by, {}};
    }
    case 4728: case 4732: case 4756: case 4729: case 4733: case 4757: {
      const bool added = event.eventId == 4728 || event.eventId == 4732 || event.eventId == 4756;
      auto privileged = PrivilegedGroupName(Field(event, L"TargetSid"));
      if (privileged.empty() && Lower(target) == L"dnsadmins") privileged = L"DnsAdmins";
      auto member = Field(event, L"MemberName");
      if (!Filled(member)) member = Field(event, L"MemberSid");
      // CN=Jo Bloggs,OU=... -> Jo Bloggs
      if (member.rfind(L"CN=", 0) == 0) member = member.substr(3, member.find(L',') == std::wstring::npos ? std::wstring::npos : member.find(L',') - 3);
      std::wstring extra = L"\"memberDisplay\":" + J(member);
      if (!privileged.empty()) extra += L",\"privilegedGroup\":" + J(privileged);
      return {added ? L"ad.group.member_added" : L"ad.group.member_removed",
              member + (added ? L" was added to " : L" was removed from ") + target + by, extra};
    }
    case 4727: case 4731: case 4754: return {L"ad.group.created", L"Group " + target + L" was created" + by, {}};
    case 4730: case 4734: case 4758: return {L"ad.group.deleted", L"Group " + target + L" was deleted" + by, {}};
    case 4765: case 4766: return {L"ad.sidhistory.added", L"SID history was added to " + target + by, {}};
    case 4768: {
      const auto& status = Lower(Field(event, L"Status"));
      if (status == L"0x0" && Field(event, L"PreAuthType") == L"0" && Lower(target) != L"krbtgt") {
        return {L"ad.kerberos.asrep", L"Kerberos ticket issued without pre-authentication for " + target + L" (AS-REP roastable)", {}};
      }
      if (status == L"0x6" || status == L"0x12" || status == L"0x18") {
        return {L"ad.kerberos.tgt_failed", L"Kerberos sign-in failed for " + target + L" (" + status + L")", {}};
      }
      return {};
    }
    case 4769: {
      const auto encryption = Lower(Field(event, L"TicketEncryptionType"));
      const auto& service = Field(event, L"ServiceName");
      if ((encryption != L"0x17" && encryption != L"0x18") || Lower(Field(event, L"Status")) != L"0x0" || MachineAccount(service) ||
          Lower(service) == L"krbtgt") {
        return {};
      }
      return {L"ad.kerberos.rc4_service_ticket", target + L" requested an RC4 service ticket for " + service + L" (Kerberoasting pattern)", {}};
    }
    case 4771: {
      const auto status = Lower(Field(event, L"Status"));
      if (status != L"0x18" && status != L"0x12") return {};
      return {L"ad.kerberos.preauth_failed", L"Kerberos pre-authentication failed for " + target, {}};
    }
    case 4776: {
      const auto status = Lower(Field(event, L"Status"));
      if (status == L"0x0" || status.empty()) return {};
      return {L"ad.ntlm.failed", L"NTLM sign-in failed for " + target + L" from " + Field(event, L"Workstation"), {}};
    }
    case 4662: {
      // DCSync: a non-DC account using the "replicate directory changes (all / filtered set)" rights.
      const auto properties = Lower(Field(event, L"Properties"));
      const bool replication = properties.find(L"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") != std::wstring::npos ||
                               properties.find(L"89e95b76-444d-4c62-991a-0facbeda640c") != std::wstring::npos;
      if (!replication || MachineAccount(subject)) return {};
      const auto lower = Lower(subject);
      const bool sync = lower.rfind(L"msol_", 0) == 0 || lower.rfind(L"aad_", 0) == 0 || lower.rfind(L"sync_", 0) == 0;
      return {L"ad.replication.requested", subject + L" requested directory replication (DCSync rights)",
              sync ? L"\"knownSyncAccount\":true" : L"\"knownSyncAccount\":false"};
    }
    case 5136: case 5137: case 5141: {
      const auto dn = Lower(Field(event, L"ObjectDN"));
      const auto objectClass = Lower(Field(event, L"ObjectClass"));
      const auto attribute = Field(event, L"AttributeLDAPDisplayName");
      const auto verb = event.eventId == 5137 ? L"created" : event.eventId == 5141 ? L"deleted" : L"modified";
      if (dn.find(L"cn=adminsdholder,cn=system") != std::wstring::npos) {
        return {L"ad.adminsdholder.modified", L"AdminSDHolder was " + std::wstring(verb) + by, {}};
      }
      if (objectClass == L"grouppolicycontainer") {
        return {L"ad.gpo.changed", L"Group Policy object " + Field(event, L"ObjectDN") + L" was " + verb + by, {}};
      }
      static const std::vector<std::wstring> sensitive = {L"msDS-AllowedToActOnBehalfOfOtherIdentity", L"msDS-KeyCredentialLink",
                                                          L"msDS-AllowedToDelegateTo", L"servicePrincipalName", L"sIDHistory",
                                                          L"scriptPath", L"gPLink"};
      const bool domainAcl = objectClass == L"domaindns" && attribute == L"nTSecurityDescriptor";
      if (event.eventId == 5136 && (domainAcl || std::find(sensitive.begin(), sensitive.end(), attribute) != sensitive.end())) {
        return {L"ad.object.sensitive_change", attribute + L" changed on " + Field(event, L"ObjectDN") + by, {}};
      }
      return {};
    }
    case 4706: return {L"ad.trust.created", L"A domain trust to " + Field(event, L"DomainName") + L" was created" + by, {}};
    case 4707: return {L"ad.trust.removed", L"A domain trust to " + Field(event, L"DomainName") + L" was removed" + by, {}};
    case 4716: return {L"ad.trust.changed", L"A domain trust to " + Field(event, L"DomainName") + L" was changed" + by, {}};
    case 4713: return {L"ad.policy.kerberos_changed", L"Kerberos policy was changed" + by, {}};
    case 4739: return {L"ad.policy.domain_changed", L"Domain policy was changed" + by, {}};
    case 4794: return {L"ad.dsrm.password_set", L"An attempt was made to set the DSRM administrator password" + by, {}};
    case 1102: return {L"ad.log.cleared", L"The Security log on this domain controller was cleared" + by, {}};
    default: return {};
  }
}

}  // namespace admonitor

}  // namespace antivirus::agent
