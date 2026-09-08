#include "test/mocks/network/mocks.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

#include "contrib/postgres_proxy/filters/network/source/config.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace PostgresProxy {
namespace {

TEST(PostgresConfigTest, CreatesFilterWithRules) {
  envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy config;
  config.set_stat_prefix("postgres");
  config.mutable_rules();
  testing::NiceMock<Server::Configuration::MockFactoryContext> context;
  PostgresConfigFactory factory;
  auto callback = factory.createFilterFactoryFromProto(config, context);
  ASSERT_TRUE(callback.ok());
  testing::StrictMock<Network::MockFilterManager> manager;
  EXPECT_CALL(manager, addFilter(testing::_));
  (*callback)(manager);
}

TEST(PostgresConfigTest, CreatesNestedNetworkRules) {
  envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy config;
  TestUtility::loadFromYaml(R"EOF(
stat_prefix: postgres
rules:
  policies:
    network:
      permissions:
      - and_rules:
          rules:
          - or_rules:
              rules:
              - not_rule: {destination_port: 1}
      principals:
      - and_ids:
          ids:
          - or_ids:
              ids:
              - not_id: {direct_remote_ip: {address_prefix: "127.0.0.1", prefix_len: 32}}
)EOF",
                            config);
  testing::NiceMock<Server::Configuration::MockFactoryContext> context;
  PostgresConfigFactory factory;
  EXPECT_TRUE(factory.createFilterFactoryFromProto(config, context).ok());
}

class PostgresInvalidRulesTest : public testing::TestWithParam<std::string> {};

TEST_P(PostgresInvalidRulesTest, RejectsHttpMatchers) {
  envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy config;
  TestUtility::loadFromYaml(
      "stat_prefix: postgres\nrules:\n  policies:\n    invalid:\n" + GetParam(), config);
  testing::NiceMock<Server::Configuration::MockFactoryContext> context;
  PostgresConfigFactory factory;
  auto callback = factory.createFilterFactoryFromProto(config, context);
  ASSERT_FALSE(callback.ok());
  EXPECT_THAT(callback.status().message(), testing::HasSubstr("does not support HTTP or route"));
}

INSTANTIATE_TEST_SUITE_P(
    Rules, PostgresInvalidRulesTest,
    testing::Values(
        "      permissions: [{not_rule: {header: {name: x-user, present_match: true}}}]\n"
        "      principals: [{any: true}]\n",
        "      permissions: [{any: true}]\n"
        "      principals: [{or_ids: {ids: [{header: {name: x-user, present_match: true}}]}}]\n",
        "      permissions: [{url_path: {path: {exact: /billing}}}]\n"
        "      principals: [{any: true}]\n"));

} // namespace
} // namespace PostgresProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
