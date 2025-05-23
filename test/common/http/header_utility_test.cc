#include <regex>
#include <vector>

#include "envoy/config/route/v3/route_components.pb.h"
#include "envoy/http/protocol.h"
#include "envoy/json/json_object.h"

#include "source/common/http/header_utility.h"
#include "source/common/json/json_loader.h"

#include "test/mocks/http/header_validator.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

using testing::ElementsAre;

namespace Envoy {
namespace Http {

envoy::config::route::v3::HeaderMatcher parseHeaderMatcherFromYaml(const std::string& yaml) {
  envoy::config::route::v3::HeaderMatcher header_matcher;
  TestUtility::loadFromYaml(yaml, header_matcher);
  return header_matcher;
}

class HeaderUtilityTest : public testing::Test {
public:
  const HeaderEntry& hostHeaderEntry(const std::string& host_value, bool set_connect = false) {
    headers_.setHost(host_value);
    if (set_connect) {
      headers_.setMethod(Http::Headers::get().MethodValues.Connect);
    }
    return *headers_.Host();
  }
  TestRequestHeaderMapImpl headers_;
};

TEST_F(HeaderUtilityTest, HasHost) {
  const std::vector<std::pair<std::string, bool>> host_headers{
      {"localhost", false},      // w/o port part
      {"localhost:443", true},   // name w/ port
      {"", false},               // empty
      {":443", true},            // just port
      {"192.168.1.1", false},    // ipv4
      {"192.168.1.1:443", true}, // ipv4 w/ port
      {"[fc00::1]:443", true},   // ipv6 w/ port
      {"[fc00::1]", false},      // ipv6
  };

  for (const auto& host_pair : host_headers) {
    EXPECT_EQ(HeaderUtility::getPortStart(host_pair.first) != absl::string_view::npos,
              host_pair.second)
        << host_pair.first;
  }
}

TEST_F(HeaderUtilityTest, HostHasPort) {
  const std::vector<std::pair<std::string, bool>> host_headers{
      {"localhost", false},      // w/o port part
      {"localhost:443", true},   // name w/ port
      {"", false},               // empty
      {":443", true},            // just port
      {"192.168.1.1", false},    // ipv4
      {"192.168.1.1:443", true}, // ipv4 w/ port
      {"[fc00::1]:443", true},   // ipv6 w/ port
      {"[fc00::1]", false},      // ipv6
      {":", false},              // malformed string #1
      {"]:", false},             // malformed string #2
      {":abc", false},           // malformed string #3
  };

  for (const auto& host_pair : host_headers) {
    EXPECT_EQ(host_pair.second, HeaderUtility::hostHasPort(host_pair.first));
  }
}

// Port's part from host header get removed
TEST_F(HeaderUtilityTest, RemovePortsFromHost) {
  const std::vector<std::pair<std::string, std::string>> host_headers{
      {"localhost", "localhost"},           // w/o port part
      {"localhost:443", "localhost"},       // name w/ port
      {"", ""},                             // empty
      {":443", ""},                         // just port
      {"192.168.1.1", "192.168.1.1"},       // ipv4
      {"192.168.1.1:443", "192.168.1.1"},   // ipv4 w/ port
      {"[fc00::1]:443", "[fc00::1]"},       // ipv6 w/ port
      {"[fc00::1]", "[fc00::1]"},           // ipv6
      {":", ":"},                           // malformed string #1
      {"]:", "]:"},                         // malformed string #2
      {":abc", ":abc"},                     // malformed string #3
      {"localhost:80", "localhost:80"},     // port not matching w/ hostname
      {"192.168.1.1:80", "192.168.1.1:80"}, // port not matching w/ ipv4
      {"[fc00::1]:80", "[fc00::1]:80"}      // port not matching w/ ipv6
  };

  const std::vector<std::pair<std::string, std::string>> any_host_headers{
      {"localhost:9999", "localhost"}, // name any port
  };

  for (const auto& host_pair : host_headers) {
    auto& host_header = hostHeaderEntry(host_pair.first);
    HeaderUtility::stripPortFromHost(headers_, 443);
    EXPECT_EQ(host_header.value().getStringView(), host_pair.second);
  }
  for (const auto& host_pair : any_host_headers) {
    auto& host_header = hostHeaderEntry(host_pair.first);
    HeaderUtility::stripPortFromHost(headers_, absl::nullopt);
    EXPECT_EQ(host_header.value().getStringView(), host_pair.second);
  }
}

TEST_F(HeaderUtilityTest, RemovePortsFromHostConnect) {
  const std::vector<std::pair<std::string, std::string>> host_headers{
      {"localhost:443", "localhost"},
  };
  for (const auto& host_pair : host_headers) {
    auto& host_header = hostHeaderEntry(host_pair.first, true);
    HeaderUtility::stripPortFromHost(headers_, 443);
    EXPECT_EQ(host_header.value().getStringView(), host_pair.second);
  }
}

// Host's trailing dot from host header get removed.
TEST_F(HeaderUtilityTest, RemoveTrailingDotFromHost) {
  const std::vector<std::pair<std::string, std::string>> host_headers{
      {"localhost", "localhost"},      // w/o dot
      {"localhost.", "localhost"},     // name w/ dot
      {"", ""},                        // empty
      {"192.168.1.1", "192.168.1.1"},  // ipv4
      {"abc.com", "abc.com"},          // dns w/o dot
      {"abc.com.", "abc.com"},         // dns w/ dot
      {"abc.com:443", "abc.com:443"},  // dns port w/o dot
      {"abc.com.:443", "abc.com:443"}, // dns port w/ dot
      {"[fc00::1]", "[fc00::1]"},      // ipv6
      {":", ":"},                      // malformed string #1
      {"]:", "]:"},                    // malformed string #2
      {":abc", ":abc"},                // malformed string #3
      {".", ""},                       // malformed string #4
      {"..", "."},                     // malformed string #5
      {".123", ".123"},                // malformed string #6
      {".:.", ".:"}                    // malformed string #7
  };

  for (const auto& host_pair : host_headers) {
    auto& host_header = hostHeaderEntry(host_pair.first);
    HeaderUtility::stripTrailingHostDot(headers_);
    EXPECT_EQ(host_header.value().getStringView(), host_pair.second);
  }
}

TEST(GetAllOfHeaderAsStringTest, All) {
  const LowerCaseString test_header("test");
  {
    TestRequestHeaderMapImpl headers;
    const auto ret = HeaderUtility::getAllOfHeaderAsString(headers, test_header);
    EXPECT_FALSE(ret.result().has_value());
    EXPECT_TRUE(ret.backingString().empty());
  }
  {
    TestRequestHeaderMapImpl headers{{"test", "foo"}};
    const auto ret = HeaderUtility::getAllOfHeaderAsString(headers, test_header);
    EXPECT_EQ("foo", ret.result().value());
    EXPECT_TRUE(ret.backingString().empty());
  }
  {
    TestRequestHeaderMapImpl headers{{"test", "foo"}, {"test", "bar"}};
    const auto ret = HeaderUtility::getAllOfHeaderAsString(headers, test_header);
    EXPECT_EQ("foo,bar", ret.result().value());
    EXPECT_EQ("foo,bar", ret.backingString());
  }
  {
    TestRequestHeaderMapImpl headers{{"test", ""}, {"test", "bar"}};
    const auto ret = HeaderUtility::getAllOfHeaderAsString(headers, test_header);
    EXPECT_EQ(",bar", ret.result().value());
    EXPECT_EQ(",bar", ret.backingString());
  }
  {
    TestRequestHeaderMapImpl headers{{"test", ""}, {"test", ""}};
    const auto ret = HeaderUtility::getAllOfHeaderAsString(headers, test_header);
    EXPECT_EQ(",", ret.result().value());
    EXPECT_EQ(",", ret.backingString());
  }
  {
    TestRequestHeaderMapImpl headers{
        {"test", "a"}, {"test", "b"}, {"test", "c"}, {"test", ""}, {"test", ""}};
    const auto ret = HeaderUtility::getAllOfHeaderAsString(headers, test_header);
    EXPECT_EQ("a,b,c,,", ret.result().value());
    EXPECT_EQ("a,b,c,,", ret.backingString());
    // Make sure copying the return value works correctly.
    const auto ret2 = ret; // NOLINT(performance-unnecessary-copy-initialization)
    EXPECT_EQ(ret2.result(), ret.result());
    EXPECT_EQ(ret2.backingString(), ret.backingString());
    EXPECT_EQ(ret2.result().value().data(), ret2.backingString().data());
    EXPECT_NE(ret2.result().value().data(), ret.backingString().data());
  }
}

class MatchHeadersTest : public ::testing::Test {
public:
  NiceMock<Server::Configuration::MockServerFactoryContext> context_;
};

TEST_F(MatchHeadersTest, MayMatchOneOrMoreRequestHeader) {
  TestRequestHeaderMapImpl headers{{"some-header", "a"}, {"other-header", "b"}};

  const std::string yaml = R"EOF(
name: match-header
string_match:
  safe_regex:
    google_re2: {}
    regex: (a|b)
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_FALSE(HeaderUtility::matchHeaders(headers, header_data));

  headers.addCopy("match-header", "a");
  // With a single "match-header" this regex will match.
  EXPECT_TRUE(HeaderUtility::matchHeaders(headers, header_data));

  headers.addCopy("match-header", "b");
  // With two "match-header" we now logically have "a,b" as the value, so the regex will not match.
  EXPECT_FALSE(HeaderUtility::matchHeaders(headers, header_data));

  header_data[0] = HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(R"EOF(
name: match-header
string_match:
  exact: a,b
  )EOF"),
                                                   context_);
  // Make sure that an exact match on "a,b" does in fact work.
  EXPECT_TRUE(HeaderUtility::matchHeaders(headers, header_data));
}

TEST_F(MatchHeadersTest, MustMatchAllHeaderData) {
  TestRequestHeaderMapImpl matching_headers_1{{"match-header-A", "1"}, {"match-header-B", "2"}};
  TestRequestHeaderMapImpl matching_headers_2{
      {"match-header-A", "3"}, {"match-header-B", "4"}, {"match-header-C", "5"}};
  TestRequestHeaderMapImpl unmatching_headers_1{{"match-header-A", "6"}};
  TestRequestHeaderMapImpl unmatching_headers_2{{"match-header-B", "7"}};
  TestRequestHeaderMapImpl unmatching_headers_3{{"match-header-A", "8"}, {"match-header-C", "9"}};
  TestRequestHeaderMapImpl unmatching_headers_4{{"match-header-C", "10"}, {"match-header-D", "11"}};

  const std::string yamlA = R"EOF(
name: match-header-A
  )EOF";

  const std::string yamlB = R"EOF(
name: match-header-B
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yamlA), context_));
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yamlB), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers_1, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers_2, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers_1, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers_2, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers_3, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers_4, header_data));
}

TEST_F(MatchHeadersTest, HeaderPresence) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"other-header", "value"}};
  const std::string yaml = R"EOF(
name: match-header
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderPresenceTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"other-header", "value"}};
  TestRequestHeaderMapImpl empty_headers{{}};
  const std::string yaml = R"EOF(
name: match-header
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderExactMatch)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "match-value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "other-value"},
                                              {"other-header", "match-value"}};
  const std::string yaml = R"EOF(
name: match-header
exact_match: match-value
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderExactMatchInverse)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "other-value"},
                                            {"other-header", "match-value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "match-value"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
exact_match: match-value
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderExactMatchInverseTreatMissingAsEmpty)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "other-value"},
                                            {"other-header", "match-value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "match-value"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
exact_match: match-value
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderSafeRegexMatch)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "1234"},
                                              {"match-header", "123.456"}};
  const std::string yaml = R"EOF(
name: match-header
safe_regex_match:
  google_re2: {}
  regex: \d{3}
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderSafeRegexInverseMatch)) {
  TestDeprecatedV2Api _deprecated_v2_api;
  TestRequestHeaderMapImpl matching_headers{{"match-header", "1234"}, {"match-header", "123.456"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
safe_regex_match:
  google_re2: {}
  regex: \d{3}
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderSafeRegexInverseMatchTreatMissingAsEmpty)) {
  TestDeprecatedV2Api _deprecated_v2_api;
  TestRequestHeaderMapImpl matching_headers{{"match-header", "1234"}, {"match-header", "123.456"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
safe_regex_match:
  google_re2: {}
  regex: \d{3}
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderRangeMatch) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "-1"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "0"},
                                              {"match-header", "somestring"},
                                              {"match-header", "10.9"},
                                              {"match-header", "-1somestring"}};
  const std::string yaml = R"EOF(
name: match-header
range_match:
  start: -10
  end: 0
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderRangeInverseMatch) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "0"},
                                            {"match-header", "somestring"},
                                            {"match-header", "10.9"},
                                            {"match-header", "-1somestring"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "-1"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
range_match:
  start: -10
  end: 0
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderRangeInverseMatchTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "0"},
                                            {"match-header", "somestring"},
                                            {"match-header", "10.9"},
                                            {"match-header", "-1somestring"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "-1"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
range_match:
  start: -10
  end: 0
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

// Test the case present_match is true. Expected true when
// header matched, expected false when no header matched.
TEST_F(MatchHeadersTest, HeaderPresentMatchWithTrueValue) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl unmatching_headers{{"nonmatch-header", "1234"},
                                              {"other-nonmatch-header", "123.456"}};

  const std::string yaml = R"EOF(
name: match-header
present_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

// Test the case present_match is true and treat_missing_header_as_empty is
// true. Expected always return match.
TEST_F(MatchHeadersTest, HeaderPresentMatchWithTrueValueTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl unmatching_headers{{"nonmatch-header", "1234"},
                                              {"other-nonmatch-header", "123.456"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
present_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

// Test the case present_match is false. Expected false when
// header matched, expected true when no header matched.
TEST_F(MatchHeadersTest, HeaderPresentMatchWithFalseValue) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl unmatching_headers{{"nonmatch-header", "1234"},
                                              {"other-nonmatch-header", "123.456"}};

  const std::string yaml = R"EOF(
name: match-header
present_match: false
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_FALSE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

// Test the case present_match is false and treat_missing_header_as_empty is
// true. Expected always return no match.
TEST_F(MatchHeadersTest, HeaderPresentMatchWithFalseValueTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl unmatching_headers{{"nonmatch-header", "1234"},
                                              {"other-nonmatch-header", "123.456"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
present_match: false
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_FALSE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

// Test the case present_match is true and invert_match is true. Expected true when
// no header matched, expected false when header matched.
TEST_F(MatchHeadersTest, HeaderPresentInverseMatchWithTrueValue) {
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl matching_headers{{"nonmatch-header", "1234"},
                                            {"other-nonmatch-header", "123.456"}};

  const std::string yaml = R"EOF(
name: match-header
present_match: true
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

// Test the case present_match is true, invert_match is true, and
// treat_missing_header_as_empty is true. Expected always return false.
TEST_F(MatchHeadersTest, HeaderPresentInverseMatchWithTrueValueTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl matching_headers{{"nonmatch-header", "1234"},
                                            {"other-nonmatch-header", "123.456"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
present_match: true
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_FALSE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

// Test the case present_match is true and invert_match is true. Expected false when
// no header matched, expected true when header matched.
TEST_F(MatchHeadersTest, HeaderPresentInverseMatchWithFalseValue) {
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl matching_headers{{"nonmatch-header", "1234"},
                                            {"other-nonmatch-header", "123.456"}};

  const std::string yaml = R"EOF(
name: match-header
present_match: false
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_FALSE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

// Test the case present_match is true and invert_match is true. Expected false
// when no header matched, expected true when header matched.
TEST_F(MatchHeadersTest, HeaderPresentInverseMatchWithFalseValueTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123"}};
  TestRequestHeaderMapImpl matching_headers{{"nonmatch-header", "1234"},
                                            {"other-nonmatch-header", "123.456"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
present_match: false
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderPrefixMatch)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "value123"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123value"}};

  const std::string yaml = R"EOF(
name: match-header
prefix_match: value
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderPrefixMatchTreatMissingAsEmpty)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "value123"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123value"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
prefix_match: value
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderPrefixInverseMatch)) {
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "value123"}};
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123value"}};

  const std::string yaml = R"EOF(
name: match-header
prefix_match: value
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderPrefixInverseMatchTreatMissingAsEmpty)) {
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "value123"}};
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123value"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
prefix_match: value
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderSuffixMatch)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "value123"}};

  const std::string yaml = R"EOF(
name: match-header
suffix_match: value
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderSuffixMatchTreatMissingAsEmpty)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "value123"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
suffix_match: value
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderSuffixInverseMatch)) {
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123value"}};
  TestRequestHeaderMapImpl matching_headers{{"match-header", "value123"}};

  const std::string yaml = R"EOF(
name: match-header
suffix_match: value
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderSuffixInverseMatchTreatMissingAsEmpty)) {
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123value"}};
  TestRequestHeaderMapImpl matching_headers{{"match-header", "value123"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
suffix_match: value
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderContainsMatch)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123onevalue456"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123anothervalue456"}};

  const std::string yaml = R"EOF(
name: match-header
contains_match: onevalue
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderContainsMatchTreatMissngAsEmpty)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123onevalue456"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123anothervalue456"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
contains_match: onevalue
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderContainsInverseMatch)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123onevalue456"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123anothervalue456"}};

  const std::string yaml = R"EOF(
name: match-header
contains_match: onevalue
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(matching_headers, header_data));
}

TEST_F(MatchHeadersTest, DEPRECATED_FEATURE_TEST(HeaderContainsInverseMatchTreatMissingAsEmpty)) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "123onevalue456"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123anothervalue456"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
contains_match: onevalue
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderStringMatch) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "match-value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "other-value"},
                                              {"other-header", "match-value"}};
  const std::string yaml = R"EOF(
name: match-header
string_match:
  exact: match-value
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderStringMatchTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "match-value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "other-value"},
                                              {"other-header", "match-value"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
string_match:
  exact: match-value
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderStringMatchIgnoreCase) {
  TestRequestHeaderMapImpl matching_headers_1{{"match-header", "123onevalue456"}};
  TestRequestHeaderMapImpl matching_headers_2{{"match-header", "123OneValue456"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123anothervalue456"}};

  const std::string yaml = R"EOF(
name: match-header
string_match:
  contains: onevalue
  ignore_case: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers_1, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers_2, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderStringMatchIgnoreCaseTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl matching_headers_1{{"match-header", "123onevalue456"}};
  TestRequestHeaderMapImpl matching_headers_2{{"match-header", "123OneValue456"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "123anothervalue456"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
string_match:
  contains: onevalue
  ignore_case: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers_1, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers_2, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderStringMatchInverse) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "other-value"},
                                            {"other-header", "match-value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "match-value"}};

  const std::string yaml = R"EOF(
name: match-header
string_match:
  exact: match-value
invert_match: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
}

TEST_F(MatchHeadersTest, HeaderStringMatchInverseTreatMissingAsEmpty) {
  TestRequestHeaderMapImpl matching_headers{{"match-header", "other-value"},
                                            {"other-header", "match-value"}};
  TestRequestHeaderMapImpl unmatching_headers{{"match-header", "match-value"}};
  TestRequestHeaderMapImpl empty_headers{{}};

  const std::string yaml = R"EOF(
name: match-header
string_match:
  exact: match-value
invert_match: true
treat_missing_header_as_empty: true
  )EOF";

  std::vector<HeaderUtility::HeaderDataPtr> header_data;
  header_data.push_back(
      HeaderUtility::createHeaderData(parseHeaderMatcherFromYaml(yaml), context_));
  EXPECT_TRUE(HeaderUtility::matchHeaders(matching_headers, header_data));
  EXPECT_FALSE(HeaderUtility::matchHeaders(unmatching_headers, header_data));
  EXPECT_TRUE(HeaderUtility::matchHeaders(empty_headers, header_data));
}

TEST(HeaderIsValidTest, InvalidHeaderValuesAreRejected) {
  // ASCII values 1-31 are control characters (with the exception of ASCII
  // values 9, 10, and 13 which are a horizontal tab, line feed, and carriage
  // return, respectively), and are not valid in an HTTP header, per
  // RFC 7230, section 3.2
  for (int i = 0; i < 32; i++) {
    if (i == 9) {
      continue;
    }

    EXPECT_FALSE(HeaderUtility::headerValueIsValid(std::string(1, i)));
  }
}

TEST(HeaderIsValidTest, ValidHeaderValuesAreAccepted) {
  EXPECT_TRUE(HeaderUtility::headerValueIsValid("some-value"));
  EXPECT_TRUE(HeaderUtility::headerValueIsValid("Some Other Value"));
}

TEST(HeaderIsValidTest, AuthorityIsValid) {
  EXPECT_TRUE(HeaderUtility::authorityIsValid("strangebutlegal$-%&'"));
  EXPECT_FALSE(HeaderUtility::authorityIsValid("illegal{}"));
  // Validate that the "@" character is allowed.
  EXPECT_TRUE(HeaderUtility::authorityIsValid("username@example.com'"));
}

TEST(HeaderIsValidTest, IsConnect) {
  EXPECT_TRUE(HeaderUtility::isConnect(Http::TestRequestHeaderMapImpl{{":method", "CONNECT"}}));
  EXPECT_FALSE(HeaderUtility::isConnect(Http::TestRequestHeaderMapImpl{{":method", "GET"}}));
  EXPECT_FALSE(HeaderUtility::isConnect(Http::TestRequestHeaderMapImpl{}));
}

TEST(HeaderIsValidTest, IsConnectUdpRequest) {
  EXPECT_TRUE(HeaderUtility::isConnectUdpRequest(
      Http::TestRequestHeaderMapImpl{{"upgrade", "connect-udp"}}));
  // Should use case-insensitive comparison for the upgrade values.
  EXPECT_TRUE(HeaderUtility::isConnectUdpRequest(
      Http::TestRequestHeaderMapImpl{{"upgrade", "CONNECT-UDP"}}));
  // Extended CONNECT requests should be normalized to HTTP/1.1.
  EXPECT_FALSE(HeaderUtility::isConnectUdpRequest(
      Http::TestRequestHeaderMapImpl{{":method", "CONNECT"}, {":protocol", "connect-udp"}}));
  EXPECT_FALSE(HeaderUtility::isConnectUdpRequest(Http::TestRequestHeaderMapImpl{}));
}

TEST(HeaderIsValidTest, IsConnectResponse) {
  RequestHeaderMapPtr connect_request{new TestRequestHeaderMapImpl{{":method", "CONNECT"}}};
  RequestHeaderMapPtr get_request{new TestRequestHeaderMapImpl{{":method", "GET"}}};
  TestResponseHeaderMapImpl success_response{{":status", "200"}};
  TestResponseHeaderMapImpl failure_response{{":status", "500"}};

  EXPECT_TRUE(HeaderUtility::isConnectResponse(connect_request.get(), success_response));
  EXPECT_FALSE(HeaderUtility::isConnectResponse(connect_request.get(), failure_response));
  EXPECT_FALSE(HeaderUtility::isConnectResponse(nullptr, success_response));
  EXPECT_FALSE(HeaderUtility::isConnectResponse(get_request.get(), success_response));
}

TEST(HeaderIsValidTest, RewriteAuthorityForConnectUdp) {
  TestRequestHeaderMapImpl connect_udp_request{
      {":path", "/.well-known/masque/udp/foo.lyft.com/80/"}, {":authority", "example.org"}};
  EXPECT_TRUE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_request));
  EXPECT_EQ(connect_udp_request.getHostValue(), "foo.lyft.com:80");

  TestRequestHeaderMapImpl connect_udp_request_ipv6{
      {":path", "/.well-known/masque/udp/2001%3A0db8%3A85a3%3A%3A8a2e%3A0370%3A7334/80/"},
      {":authority", "example.org"}};
  EXPECT_TRUE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_request_ipv6));
  EXPECT_EQ(connect_udp_request_ipv6.getHostValue(), "[2001:0db8:85a3::8a2e:0370:7334]:80");

  TestRequestHeaderMapImpl connect_udp_request_ipv6_not_escaped{
      {":path", "/.well-known/masque/udp/2001:0db8:85a3::8a2e:0370:7334/80"},
      {":authority", "example.org"}};
  EXPECT_FALSE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_request_ipv6_not_escaped));

  TestRequestHeaderMapImpl connect_udp_request_ipv6_zoneid{
      {":path", "/.well-known/masque/udp/fe80::a%25ee1/80/"}, {":authority", "example.org"}};
  EXPECT_FALSE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_request_ipv6_zoneid));

  TestRequestHeaderMapImpl connect_udp_malformed1{
      {":path", "/well-known/masque/udp/foo.lyft.com/80/"}};
  EXPECT_FALSE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_malformed1));

  TestRequestHeaderMapImpl connect_udp_malformed2{{":path", "/masque/udp/foo.lyft.com/80/"}};
  EXPECT_FALSE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_malformed2));

  TestRequestHeaderMapImpl connect_udp_no_path{{":authority", "example.org"}};
  EXPECT_FALSE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_no_path));

  TestRequestHeaderMapImpl connect_udp_empty_host{{":path", "/.well-known/masque/udp//80/"}};
  EXPECT_FALSE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_empty_host));

  TestRequestHeaderMapImpl connect_udp_empty_port{
      {":path", "/.well-known/masque/udp/foo.lyft.com//"}};
  EXPECT_FALSE(HeaderUtility::rewriteAuthorityForConnectUdp(connect_udp_empty_port));
}

#ifdef ENVOY_ENABLE_HTTP_DATAGRAMS
TEST(HeaderIsValidTest, IsCapsuleProtocol) {
  EXPECT_TRUE(
      HeaderUtility::isCapsuleProtocol(TestRequestHeaderMapImpl{{"Capsule-Protocol", "?1"}}));
  EXPECT_TRUE(HeaderUtility::isCapsuleProtocol(
      TestRequestHeaderMapImpl{{"Capsule-Protocol", "?1;a=1;b=2;c;d=?0"}}));
  EXPECT_FALSE(
      HeaderUtility::isCapsuleProtocol(TestRequestHeaderMapImpl{{"Capsule-Protocol", "?0"}}));
  EXPECT_FALSE(HeaderUtility::isCapsuleProtocol(
      TestRequestHeaderMapImpl{{"Capsule-Protocol", "?1"}, {"Capsule-Protocol", "?1"}}));
  EXPECT_FALSE(HeaderUtility::isCapsuleProtocol(TestRequestHeaderMapImpl{{":method", "CONNECT"}}));
  EXPECT_TRUE(HeaderUtility::isCapsuleProtocol(
      TestResponseHeaderMapImpl{{":status", "200"}, {"Capsule-Protocol", "?1"}}));
  EXPECT_FALSE(HeaderUtility::isCapsuleProtocol(TestResponseHeaderMapImpl{{":status", "200"}}));
}
#endif

TEST(HeaderIsValidTest, ShouldHaveNoBody) {
  const std::vector<std::string> methods{{"CONNECT"}, {"GET"}, {"DELETE"}, {"TRACE"}, {"HEAD"}};

  for (const auto& method : methods) {
    TestRequestHeaderMapImpl headers{{":method", method}};
    EXPECT_TRUE(HeaderUtility::requestShouldHaveNoBody(headers));
  }

  TestRequestHeaderMapImpl post{{":method", "POST"}};
  EXPECT_FALSE(HeaderUtility::requestShouldHaveNoBody(post));
}

TEST(HeaderAddTest, HeaderAdd) {
  TestRequestHeaderMapImpl headers{{"myheader1", "123value"}};
  TestRequestHeaderMapImpl headers_to_add{{"myheader2", "456value"}};

  HeaderMapImpl::copyFrom(headers, headers_to_add);

  headers_to_add.iterate([&headers](const Http::HeaderEntry& entry) -> Http::HeaderMap::Iterate {
    Http::LowerCaseString lower_key{std::string(entry.key().getStringView())};
    EXPECT_EQ(entry.value().getStringView(), headers.get(lower_key)[0]->value().getStringView());
    return Http::HeaderMap::Iterate::Continue;
  });
}

TEST(HeaderIsValidTest, HeaderNameIsValid) {
  // Isn't valid but passes legacy checks.
  EXPECT_FALSE(HeaderUtility::headerNameIsValid(":"));
  EXPECT_FALSE(HeaderUtility::headerNameIsValid("::"));
  EXPECT_FALSE(HeaderUtility::headerNameIsValid("\n"));
  EXPECT_FALSE(HeaderUtility::headerNameIsValid(":\n"));
  EXPECT_FALSE(HeaderUtility::headerNameIsValid("asd\n"));

  EXPECT_TRUE(HeaderUtility::headerNameIsValid("asd"));
  // Not actually valid but passes legacy Envoy checks.
  EXPECT_TRUE(HeaderUtility::headerNameIsValid(":asd"));
}

TEST(HeaderIsValidTest, HeaderNameContainsUnderscore) {
  EXPECT_FALSE(HeaderUtility::headerNameContainsUnderscore("cookie"));
  EXPECT_FALSE(HeaderUtility::headerNameContainsUnderscore("x-something"));
  EXPECT_TRUE(HeaderUtility::headerNameContainsUnderscore("_cookie"));
  EXPECT_TRUE(HeaderUtility::headerNameContainsUnderscore("cookie_"));
  EXPECT_TRUE(HeaderUtility::headerNameContainsUnderscore("x_something"));
}

TEST(PercentEncoding, ShouldCloseConnection) {
  EXPECT_TRUE(HeaderUtility::shouldCloseConnection(Protocol::Http10,
                                                   TestRequestHeaderMapImpl{{"foo", "bar"}}));
  EXPECT_FALSE(HeaderUtility::shouldCloseConnection(
      Protocol::Http10, TestRequestHeaderMapImpl{{"connection", "keep-alive"}}));
  EXPECT_FALSE(HeaderUtility::shouldCloseConnection(
      Protocol::Http10, TestRequestHeaderMapImpl{{"connection", "foo, keep-alive"}}));

  EXPECT_FALSE(HeaderUtility::shouldCloseConnection(Protocol::Http11,
                                                    TestRequestHeaderMapImpl{{"foo", "bar"}}));
  EXPECT_TRUE(HeaderUtility::shouldCloseConnection(
      Protocol::Http11, TestRequestHeaderMapImpl{{"connection", "close"}}));
  EXPECT_TRUE(HeaderUtility::shouldCloseConnection(
      Protocol::Http11, TestRequestHeaderMapImpl{{"connection", "te,close"}}));
  EXPECT_TRUE(HeaderUtility::shouldCloseConnection(
      Protocol::Http11, TestRequestHeaderMapImpl{{"proxy-connection", "close"}}));
  EXPECT_TRUE(HeaderUtility::shouldCloseConnection(
      Protocol::Http11, TestRequestHeaderMapImpl{{"proxy-connection", "foo,close"}}));
}

TEST(RequiredHeaders, IsRemovableHeader) {
  EXPECT_FALSE(HeaderUtility::isRemovableHeader(":path"));
  EXPECT_FALSE(HeaderUtility::isRemovableHeader("host"));
  EXPECT_FALSE(HeaderUtility::isRemovableHeader("Host"));
  EXPECT_TRUE(HeaderUtility::isRemovableHeader(""));
  EXPECT_TRUE(HeaderUtility::isRemovableHeader("hostname"));
  EXPECT_TRUE(HeaderUtility::isRemovableHeader("Content-Type"));
}

TEST(RequiredHeaders, IsModifiableHeader) {
  EXPECT_FALSE(HeaderUtility::isModifiableHeader(":path"));
  EXPECT_FALSE(HeaderUtility::isModifiableHeader("host"));
  EXPECT_FALSE(HeaderUtility::isModifiableHeader("Host"));
  EXPECT_TRUE(HeaderUtility::isModifiableHeader(""));
  EXPECT_TRUE(HeaderUtility::isModifiableHeader("hostname"));
  EXPECT_TRUE(HeaderUtility::isModifiableHeader("Content-Type"));
}

TEST(ValidateHeaders, HeaderNameWithUnderscores) {
  MockHeaderValidatorStats stats;
  EXPECT_CALL(stats, incDroppedHeadersWithUnderscores());
  EXPECT_CALL(stats, incRequestsRejectedWithUnderscoresInHeaders()).Times(0u);
  EXPECT_EQ(HeaderUtility::HeaderValidationResult::DROP,
            HeaderUtility::checkHeaderNameForUnderscores(
                "header_with_underscore", envoy::config::core::v3::HttpProtocolOptions::DROP_HEADER,
                stats));

  EXPECT_CALL(stats, incDroppedHeadersWithUnderscores()).Times(0u);
  EXPECT_CALL(stats, incRequestsRejectedWithUnderscoresInHeaders());
  EXPECT_EQ(HeaderUtility::HeaderValidationResult::REJECT,
            HeaderUtility::checkHeaderNameForUnderscores(
                "header_with_underscore",
                envoy::config::core::v3::HttpProtocolOptions::REJECT_REQUEST, stats));

  EXPECT_EQ(
      HeaderUtility::HeaderValidationResult::ACCEPT,
      HeaderUtility::checkHeaderNameForUnderscores(
          "header_with_underscore", envoy::config::core::v3::HttpProtocolOptions::ALLOW, stats));

  EXPECT_EQ(HeaderUtility::HeaderValidationResult::ACCEPT,
            HeaderUtility::checkHeaderNameForUnderscores(
                "header", envoy::config::core::v3::HttpProtocolOptions::REJECT_REQUEST, stats));
}

TEST(ValidateHeaders, Connect) {
  {
    // Basic connect.
    TestRequestHeaderMapImpl headers{{":method", "CONNECT"}, {":authority", "foo.com:80"}};
    EXPECT_EQ(Http::okStatus(), HeaderUtility::checkRequiredRequestHeaders(headers));
  }
  {
    // Extended connect.
    TestRequestHeaderMapImpl headers{{":method", "CONNECT"},
                                     {":authority", "foo.com:80"},
                                     {":path", "/"},
                                     {":protocol", "websocket"}};
    EXPECT_EQ(Http::okStatus(), HeaderUtility::checkRequiredRequestHeaders(headers));
  }
  {
    // Missing path.
    TestRequestHeaderMapImpl headers{
        {":method", "CONNECT"}, {":authority", "foo.com:80"}, {":protocol", "websocket"}};
    EXPECT_NE(Http::okStatus(), HeaderUtility::checkRequiredRequestHeaders(headers));
  }
  {
    // Missing protocol.
    TestRequestHeaderMapImpl headers{
        {":method", "CONNECT"}, {":authority", "foo.com:80"}, {":path", "/"}};
    EXPECT_NE(Http::okStatus(), HeaderUtility::checkRequiredRequestHeaders(headers));
  }
}

TEST(ValidateHeaders, ContentLength) {
  bool should_close_connection;
  size_t content_length{0};
  EXPECT_EQ(
      HeaderUtility::HeaderValidationResult::ACCEPT,
      HeaderUtility::validateContentLength("1,1", true, should_close_connection, content_length));
  EXPECT_FALSE(should_close_connection);
  EXPECT_EQ(1, content_length);

  EXPECT_EQ(
      HeaderUtility::HeaderValidationResult::REJECT,
      HeaderUtility::validateContentLength("1,2", true, should_close_connection, content_length));
  EXPECT_FALSE(should_close_connection);

  EXPECT_EQ(
      HeaderUtility::HeaderValidationResult::REJECT,
      HeaderUtility::validateContentLength("1,2", false, should_close_connection, content_length));
  EXPECT_TRUE(should_close_connection);

  EXPECT_EQ(
      HeaderUtility::HeaderValidationResult::REJECT,
      HeaderUtility::validateContentLength("-1", false, should_close_connection, content_length));
  EXPECT_TRUE(should_close_connection);
}

#ifdef NDEBUG
// These tests send invalid request and response header names which violate ASSERT while creating
// such request/response headers. So they can only be run in NDEBUG mode.
TEST(ValidateHeaders, ForbiddenCharacters) {
  {
    // Valid headers
    TestRequestHeaderMapImpl headers{
        {":method", "CONNECT"}, {":authority", "foo.com:80"}, {"x-foo", "hello world"}};
    EXPECT_EQ(Http::okStatus(), HeaderUtility::checkValidRequestHeaders(headers));
  }

  {
    // Mixed case header key is ok
    TestRequestHeaderMapImpl headers{{":method", "CONNECT"}, {":authority", "foo.com:80"}};
    Http::HeaderString invalid_key(absl::string_view("x-MiXeD-CaSe"));
    headers.addViaMove(std::move(invalid_key),
                       Http::HeaderString(absl::string_view("hello world")));
    EXPECT_TRUE(HeaderUtility::checkValidRequestHeaders(headers).ok());
  }

  {
    // Invalid key
    TestRequestHeaderMapImpl headers{
        {":method", "CONNECT"}, {":authority", "foo.com:80"}, {"x-foo\r\n", "hello world"}};
    EXPECT_NE(Http::okStatus(), HeaderUtility::checkValidRequestHeaders(headers));
  }

  {
    // Invalid value
    TestRequestHeaderMapImpl headers{{":method", "CONNECT"},
                                     {":authority", "foo.com:80"},
                                     {"x-foo", "hello\r\n\r\nGET /evil HTTP/1.1"}};
    EXPECT_NE(Http::okStatus(), HeaderUtility::checkValidRequestHeaders(headers));
  }
}
#endif

TEST(ValidateHeaders, ParseCommaDelimitedHeader) {
  // Basic case
  EXPECT_THAT(HeaderUtility::parseCommaDelimitedHeader("one,two,three"),
              ElementsAre("one", "two", "three"));

  // Whitespace at the end or beginning of tokens
  EXPECT_THAT(HeaderUtility::parseCommaDelimitedHeader("one  ,two,three"),
              ElementsAre("one", "two", "three"));

  // Empty tokens are removed (from beginning, middle, and end of the string)
  EXPECT_THAT(HeaderUtility::parseCommaDelimitedHeader(", one,, two, three,,,"),
              ElementsAre("one", "two", "three"));

  // Whitespace is not removed from the middle of the tokens
  EXPECT_THAT(HeaderUtility::parseCommaDelimitedHeader("one, two, t  hree"),
              ElementsAre("one", "two", "t  hree"));

  // Semicolons are kept as part of the tokens
  EXPECT_THAT(HeaderUtility::parseCommaDelimitedHeader("one, two;foo, three"),
              ElementsAre("one", "two;foo", "three"));

  // Check that a single token is parsed regardless of commas
  EXPECT_THAT(HeaderUtility::parseCommaDelimitedHeader("foo"), ElementsAre("foo"));
  EXPECT_THAT(HeaderUtility::parseCommaDelimitedHeader(",foo,"), ElementsAre("foo"));

  // Empty string is handled
  EXPECT_TRUE(HeaderUtility::parseCommaDelimitedHeader("").empty());

  // Empty string is handled (whitespace)
  EXPECT_TRUE(HeaderUtility::parseCommaDelimitedHeader("   ").empty());

  // Empty string is handled (commas)
  EXPECT_TRUE(HeaderUtility::parseCommaDelimitedHeader(",,,").empty());
}

TEST(ValidateHeaders, GetSemicolonDelimitedAttribute) {
  // Basic case
  EXPECT_EQ(HeaderUtility::getSemicolonDelimitedAttribute("foo;bar=1"), "foo");

  // Only attribute without semicolon
  EXPECT_EQ(HeaderUtility::getSemicolonDelimitedAttribute("foo"), "foo");

  // Only attribute with semicolon
  EXPECT_EQ(HeaderUtility::getSemicolonDelimitedAttribute("foo;"), "foo");

  // Two semicolons, case 1
  EXPECT_EQ(HeaderUtility::getSemicolonDelimitedAttribute("foo;;"), "foo");

  // Two semicolons, case 2
  EXPECT_EQ(HeaderUtility::getSemicolonDelimitedAttribute(";foo;"), "");
}

TEST(ValidateHeaders, ModifyAcceptEncodingHeader) {
  // Add a new encoding
  EXPECT_EQ(HeaderUtility::addEncodingToAcceptEncoding("one,two", "three"), "one,two,three");

  // Add an already existing encoding
  EXPECT_EQ(HeaderUtility::addEncodingToAcceptEncoding("one,two", "one"), "two,one");

  // Preserve q-values for other tokens than the added encoding
  EXPECT_EQ(HeaderUtility::addEncodingToAcceptEncoding("one;q=0.3,two", "two"), "one;q=0.3,two");

  // Remove q-values for the current encoding
  EXPECT_EQ(HeaderUtility::addEncodingToAcceptEncoding("one;q=0.3,two", "one"), "two,one");

  // Add encoding to an empty header
  EXPECT_EQ(HeaderUtility::addEncodingToAcceptEncoding("", "one"), "one");
}

} // namespace Http
} // namespace Envoy
