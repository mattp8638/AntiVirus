#include "PhishingHeuristics.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace antivirus::agent {
namespace {

struct BrandProfile {
  const wchar_t* name;
  std::vector<std::wstring> trustedDomains;
  std::vector<std::wstring> tokens;
};

const std::vector<BrandProfile>& BrandProfiles() {
  static const std::vector<BrandProfile> brands = {
      {L"Microsoft", {L"microsoft.com", L"live.com", L"office.com", L"outlook.com"}, {L"microsoft", L"office", L"outlook", L"live"}},
      {L"Google", {L"google.com", L"google.co.uk", L"gmail.com"}, {L"google", L"gmail"}},
      {L"Apple", {L"apple.com", L"icloud.com"}, {L"apple", L"icloud"}},
      {L"HMRC", {L"gov.uk", L"hmrc.gov.uk"}, {L"hmrc", L"tax", L"govuk", L"gov"}},
      {L"Gov.uk", {L"gov.uk"}, {L"govuk", L"gov"}},
      {L"Royal Mail", {L"royalmail.com", L"royalmailgroup.com"}, {L"royalmail", L"royal-mail"}},
      {L"Evri", {L"evri.com"}, {L"evri", L"hermes"}},
      {L"DHL", {L"dhl.com"}, {L"dhl"}},
      {L"DPD", {L"dpd.co.uk", L"dpd.com"}, {L"dpd"}},
      {L"PayPal", {L"paypal.com"}, {L"paypal", L"pay-pal"}},
      {L"Amazon", {L"amazon.co.uk", L"amazon.com"}, {L"amazon"}},
      {L"eBay", {L"ebay.co.uk", L"ebay.com"}, {L"ebay", L"e-bay"}},
      {L"Barclays", {L"barclays.co.uk", L"barclays.com"}, {L"barclays"}},
      {L"NatWest", {L"natwest.com"}, {L"natwest", L"nat-west"}},
      {L"Lloyds", {L"lloydsbank.com"}, {L"lloyds", L"lloydsbank"}},
      {L"Santander", {L"santander.co.uk", L"santander.com"}, {L"santander"}},
      {L"HSBC", {L"hsbc.co.uk", L"hsbc.com"}, {L"hsbc"}},
      {L"Nationwide", {L"nationwide.co.uk"}, {L"nationwide"}},
      {L"Monzo", {L"monzo.com"}, {L"monzo"}},
      {L"Starling", {L"starlingbank.com"}, {L"starling", L"starlingbank"}},
  };
  return brands;
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
    return static_cast<wchar_t>(std::towlower(ch));
  });
  return value;
}

std::wstring JoinDetails(const std::vector<std::wstring>& details) {
  std::wstringstream stream;
  bool first = true;
  for (const auto& detail : details) {
    if (detail.empty()) {
      continue;
    }
    if (!first) {
      stream << L" ";
    }
    stream << detail;
    first = false;
  }
  return stream.str();
}

std::wstring ExtractHost(const DestinationContext& context) {
  if (!context.host.empty()) {
    return ToLowerCopy(context.host);
  }
  if (!context.canonicalUrl.empty()) {
    URL_COMPONENTSW components{};
    components.dwStructSize = sizeof(components);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    std::wstring mutableUrl = context.canonicalUrl;
    if (WinHttpCrackUrl(mutableUrl.data(), static_cast<DWORD>(mutableUrl.size()), 0, &components) != FALSE &&
        components.dwHostNameLength > 0) {
      return ToLowerCopy(std::wstring(components.lpszHostName, components.dwHostNameLength));
    }
  }
  return ToLowerCopy(context.normalizedIndicator);
}

std::vector<std::wstring> Split(const std::wstring& value, wchar_t delimiter) {
  std::vector<std::wstring> tokens;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == delimiter) {
      if (!current.empty()) {
        tokens.push_back(current);
      }
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  if (!current.empty()) {
    tokens.push_back(current);
  }
  return tokens;
}

std::wstring RegistrableDomain(const std::wstring& host) {
  const auto labels = Split(host, L'.');
  if (labels.size() < 2) {
    return host;
  }
  const auto last = labels[labels.size() - 1];
  const auto second = labels[labels.size() - 2];
  if (labels.size() >= 3 && last == L"uk" && (second == L"co" || second == L"org" || second == L"gov" || second == L"ac")) {
    return labels[labels.size() - 3] + L"." + second + L"." + last;
  }
  return second + L"." + last;
}

bool EndsWithDomain(const std::wstring& host, const std::wstring& trustedDomain) {
  return host == trustedDomain || (host.size() > trustedDomain.size() && host.ends_with(L"." + trustedDomain));
}

bool ContainsAny(const std::wstring& value, const std::vector<std::wstring>& needles) {
  return std::any_of(needles.begin(), needles.end(), [&](const auto& needle) {
    return !needle.empty() && value.find(needle) != std::wstring::npos;
  });
}

int LevenshteinDistance(const std::wstring& left, const std::wstring& right) {
  if (left.empty()) {
    return static_cast<int>(right.size());
  }
  if (right.empty()) {
    return static_cast<int>(left.size());
  }
  std::vector<int> previous(right.size() + 1);
  std::vector<int> current(right.size() + 1);
  for (std::size_t j = 0; j <= right.size(); ++j) {
    previous[j] = static_cast<int>(j);
  }
  for (std::size_t i = 0; i < left.size(); ++i) {
    current[0] = static_cast<int>(i + 1);
    for (std::size_t j = 0; j < right.size(); ++j) {
      const auto cost = left[i] == right[j] ? 0 : 1;
      current[j + 1] = std::min({previous[j + 1] + 1, current[j] + 1, previous[j] + cost});
    }
    previous.swap(current);
  }
  return previous[right.size()];
}

std::wstring MapConfusables(std::wstring value) {
  for (auto& ch : value) {
    switch (ch) {
      case L'а': case L'α': ch = L'a'; break;
      case L'е': case L'ε': ch = L'e'; break;
      case L'о': case L'ο': ch = L'o'; break;
      case L'р': ch = L'p'; break;
      case L'с': ch = L'c'; break;
      case L'у': ch = L'y'; break;
      case L'і': case L'í': case L'ì': ch = L'i'; break;
      case L'ј': ch = L'j'; break;
      case L'һ': ch = L'h'; break;
      case L'ӏ': case L'ⅼ': ch = L'l'; break;
      default: break;
    }
  }
  return value;
}

bool HasNonAscii(const std::wstring& value) {
  return std::any_of(value.begin(), value.end(), [](wchar_t ch) { return static_cast<unsigned int>(ch) > 127U; });
}

bool LooksLikeTyposquat(const std::wstring& host, const BrandProfile& brand) {
  const auto labels = Split(host, L'.');
  for (const auto& label : labels) {
    for (const auto& token : brand.tokens) {
      if (label == token) {
        continue;
      }
      if (label.size() >= 4 && token.size() >= 4 && LevenshteinDistance(label, token) <= 2) {
        return true;
      }
    }
  }
  return false;
}

const std::vector<std::wstring>& SuspiciousTlds() {
  static const std::vector<std::wstring> tlds = {L"top", L"click", L"cam", L"cfd", L"zip", L"mov", L"live", L"shop", L"sbs", L"cyou"};
  return tlds;
}

const std::vector<std::wstring>& CredentialKeywords() {
  static const std::vector<std::wstring> values = {L"login", L"signin", L"sign-in", L"verify", L"update", L"payment", L"pay", L"recover", L"reset", L"security", L"auth", L"invoice", L"refund", L"confirm", L"redelivery", L"parcel"};
  return values;
}

const std::vector<std::wstring>& RedirectKeywords() {
  static const std::vector<std::wstring> values = {L"redirect=", L"url=", L"next=", L"continue=", L"target=", L"return=", L"r=", L"dest="};
  return values;
}

const std::vector<std::wstring>& UrlShorteners() {
  static const std::vector<std::wstring> values = {L"bit.ly", L"tinyurl.com", L"t.co", L"ow.ly", L"rb.gy", L"buff.ly", L"rebrand.ly", L"cutt.ly", L"is.gd", L"goo.gl"};
  return values;
}

void AddReason(std::vector<DestinationReasonCode>& reasons, DestinationReasonCode reason) {
  if (std::find(reasons.begin(), reasons.end(), reason) == reasons.end()) {
    reasons.push_back(reason);
  }
}

}  // namespace

PhishingHeuristicAssessment ScorePhishingHeuristics(const DestinationContext& context) {
  PhishingHeuristicAssessment assessment{};
  const auto host = ExtractHost(context);
  const auto registrable = RegistrableDomain(host);
  const auto hostMapped = MapConfusables(host);
  const auto url = ToLowerCopy(context.canonicalUrl.empty() ? context.normalizedIndicator : context.canonicalUrl);

  std::uint32_t score = 0;
  std::vector<DestinationReasonCode> reasons;
  std::vector<std::wstring> details;

  const auto hostLabels = Split(host, L'.');
  if (hostLabels.size() > 4) {
    score += 10;
    AddReason(reasons, DestinationReasonCode::ExcessiveSubdomainDepth);
    details.push_back(L"The domain uses an unusually deep subdomain chain.");
  }

  if (hostLabels.size() >= 2) {
    const auto tld = hostLabels.back();
    if (std::find(SuspiciousTlds().begin(), SuspiciousTlds().end(), tld) != SuspiciousTlds().end()) {
      score += 16;
      AddReason(reasons, DestinationReasonCode::SuspiciousTld);
      details.push_back(L"The destination uses a high-risk top-level domain.");
    }
  }

  if (!context.fromCache && host.find(L'-') != std::wstring::npos && score >= 16) {
    score += 10;
    AddReason(reasons, DestinationReasonCode::SuspiciousNewlyRegisteredDomain);
    details.push_back(L"The destination looks like a newly registered campaign domain.");
  }

  if (url.find(L"%2f") != std::wstring::npos || url.find(L"%3a") != std::wstring::npos || url.find(L"%40") != std::wstring::npos) {
    score += 8;
    AddReason(reasons, DestinationReasonCode::EncodedParameters);
    details.push_back(L"The URL contains heavily encoded parameters.");
  }

  const auto queryTokenCount = std::count(url.begin(), url.end(), L'&');
  if (queryTokenCount >= 5) {
    score += 8;
    AddReason(reasons, DestinationReasonCode::ExcessiveQueryTokens);
    details.push_back(L"The URL has an unusually large number of query parameters.");
  }

  if (ContainsAny(url, RedirectKeywords()) && (url.find(L"http://") != std::wstring::npos || url.find(L"https://") != std::wstring::npos || url.find(L"%2f%2f") != std::wstring::npos)) {
    score += 18;
    AddReason(reasons, DestinationReasonCode::SuspiciousRedirectChain);
    details.push_back(L"The URL appears to contain a redirect chain.");
  }

  if (std::find(UrlShorteners().begin(), UrlShorteners().end(), registrable) != UrlShorteners().end()) {
    score += 20;
    AddReason(reasons, DestinationReasonCode::UrlShortenerRisk);
    details.push_back(L"The destination uses a URL shortener often abused in phishing.");
  }

  if (ContainsAny(url, CredentialKeywords())) {
    score += 12;
    AddReason(reasons, DestinationReasonCode::CredentialHarvestingKeyword);
    details.push_back(L"The destination includes login, verification, recovery, or payment wording.");
  }

  for (const auto& brand : BrandProfiles()) {
    const auto tokenMatch = ContainsAny(hostMapped, brand.tokens) || ContainsAny(url, brand.tokens);
    const auto trustedDomain = std::any_of(brand.trustedDomains.begin(), brand.trustedDomains.end(), [&](const auto& trusted) {
      return EndsWithDomain(host, trusted);
    });

    if (tokenMatch && !trustedDomain) {
      score += 24;
      AddReason(reasons, DestinationReasonCode::BrandImpersonation);
      AddReason(reasons, DestinationReasonCode::MismatchedBrandDomain);
      assessment.impersonatedBrand = brand.name;
      details.push_back(L"The destination references " + std::wstring(brand.name) + L" but is not hosted on an expected domain.");
    }

    if (!trustedDomain && LooksLikeTyposquat(hostMapped, brand)) {
      score += 32;
      AddReason(reasons, DestinationReasonCode::TyposquattingMatch);
      assessment.impersonatedBrand = brand.name;
      details.push_back(L"The domain looks like a misspelt version of " + std::wstring(brand.name) + L".");
    }

    if (!trustedDomain && HasNonAscii(host) && ContainsAny(hostMapped, brand.tokens)) {
      score += 34;
      AddReason(reasons, DestinationReasonCode::HomographMatch);
      assessment.impersonatedBrand = brand.name;
      details.push_back(L"The domain uses lookalike characters associated with " + std::wstring(brand.name) + L" impersonation.");
    }
  }

  assessment.confidence = std::min<std::uint32_t>(score, 95);
  assessment.reasonCodes = std::move(reasons);
  assessment.details = JoinDetails(details);
  assessment.suspicious = assessment.confidence >= 35;

  if (assessment.confidence >= 70) {
    assessment.category = DestinationThreatCategory::Phishing;
  } else if (assessment.confidence >= 40) {
    assessment.category = DestinationThreatCategory::Suspicious;
  } else {
    assessment.category = DestinationThreatCategory::Unknown;
  }

  return assessment;
}

}  // namespace antivirus::agent
