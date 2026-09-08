#include "source/extensions/filters/common/rbac/engine_impl.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "test/mocks/network/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/ssl/mocks.h"
#include "test/test_common/utility.h"

#include "contrib/postgres_proxy/filters/network/source/postgres_filter.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace PostgresProxy {
namespace {

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::ReturnRef;
using namespace std::literals::string_literals;

class PostgresRbacTest : public testing::Test {
protected:
  PostgresRbacTest() {
    PostgresFilterConfig::PostgresFilterConfigOptions options{
        "test.", false, false,
        envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE,
        envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE};
    config_ = std::make_shared<PostgresFilterConfig>(options, *store_.rootScope());
    filter_ = std::make_unique<PostgresFilter>(config_);
    EXPECT_CALL(read_, connection()).WillRepeatedly(ReturnRef(connection_));
    EXPECT_CALL(connection_, streamInfo()).WillRepeatedly(ReturnRef(info_));
    ON_CALL(info_, setDynamicMetadata(_, _))
        .WillByDefault(Invoke([this](const std::string& name, const Protobuf::Struct& value) {
          (*info_.metadata_.mutable_filter_metadata())[name].MergeFrom(value);
        }));
    ON_CALL(connection_, ssl()).WillByDefault(Return(nullptr));
    filter_->initializeReadFilterCallbacks(read_);
    filter_->initializeWriteFilterCallbacks(write_);
  }

  void rules(const std::string& yaml) {
    envoy::config::rbac::v3::RBAC rules;
    TestUtility::loadFromYaml(yaml, rules);
    config_->rules_ = std::make_unique<Filters::Common::RBAC::RoleBasedAccessControlEngineImpl>(
        rules, ProtobufMessage::getStrictValidationVisitor(), context_);
  }

  std::string startup(const std::string& body = "user\0app\0database\0billing\0\0"s) {
    Buffer::OwnedImpl packet;
    packet.writeBEInt<uint32_t>(8 + body.size());
    packet.writeBEInt<uint32_t>(Postgres::Protocol::POSTGRES_PROTOCOL_VERSION_30);
    packet.add(body);
    return packet.toString();
  }

  void expectDenied() {
    EXPECT_CALL(read_, injectReadDataToFilterChain(_, _)).Times(0);
    EXPECT_CALL(write_, injectWriteDataToFilterChain(_, false))
        .WillOnce(Invoke([](Buffer::Instance& data, bool) {
          EXPECT_EQ('E', data.peekBEInt<char>(0));
          EXPECT_THAT(data.toString(), testing::HasSubstr("28000"));
        }));
    EXPECT_CALL(connection_, close(Network::ConnectionCloseType::FlushWrite));
  }

  const Protobuf::Struct& metadata() {
    return info_.metadata_.filter_metadata().at(NetworkFilterNames::get().PostgresProxy);
  }

  Stats::IsolatedStoreImpl store_;
  testing::NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  testing::StrictMock<Network::MockReadFilterCallbacks> read_;
  testing::StrictMock<Network::MockWriteFilterCallbacks> write_;
  testing::NiceMock<Network::MockConnection> connection_;
  testing::NiceMock<StreamInfo::MockStreamInfo> info_;
  PostgresFilterConfigSharedPtr config_;
  std::unique_ptr<PostgresFilter> filter_;
};

constexpr char BillingRules[] = R"EOF(
action: ALLOW
policies:
  billing:
    principals:
    - any: true
    permissions:
    - and_rules:
        rules:
        - metadata:
            filter: envoy.filters.network.postgres_proxy
            path: [{key: startup}, {key: user}]
            value: {string_match: {exact: app}}
        - metadata:
            filter: envoy.filters.network.postgres_proxy
            path: [{key: startup}, {key: database}]
            value: {string_match: {exact: billing}}
)EOF";

TEST_F(PostgresRbacTest, AllowsStartupWithoutSqlParsing) {
  rules(BillingRules);
  const std::string packet = startup();
  Buffer::OwnedImpl data(packet);
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(data, false));
  EXPECT_EQ(packet, data.toString());
  EXPECT_EQ(1, config_->stats_.authorization_allowed_.value());
  EXPECT_EQ(
      "billing",
      metadata().fields().at("authorization").struct_value().fields().at("policy").string_value());
}

TEST_F(PostgresRbacTest, FragmentedStartupIsForwardedExactlyOnce) {
  rules(BillingRules);
  const std::string packet = startup();
  for (size_t i = 0; i + 1 < packet.size(); ++i) {
    Buffer::OwnedImpl fragment(packet.substr(i, 1));
    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(fragment, false));
    EXPECT_EQ(0, fragment.length());
  }
  EXPECT_EQ(0, config_->stats_.authorization_allowed_.value());
  Buffer::OwnedImpl last(packet.substr(packet.size() - 1));
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(last, false));
  EXPECT_EQ(packet, last.toString());
  EXPECT_EQ(1, config_->stats_.authorization_allowed_.value());
}

TEST_F(PostgresRbacTest, DeniesBeforeUpstreamTlsNegotiation) {
  rules(BillingRules);
  config_->upstream_ssl_ =
      envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::REQUIRE;
  expectDenied();
  Buffer::OwnedImpl data(startup("user\0app\0database\0other\0\0"s));
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
  EXPECT_EQ(0, data.length());
  data.add(startup());
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
  EXPECT_EQ(0, data.length());
  EXPECT_EQ(1, config_->stats_.authorization_denied_.value());
}

TEST_F(PostgresRbacTest, TruncatedStartupAtEndStreamIsRejected) {
  rules(BillingRules);
  expectDenied();
  Buffer::OwnedImpl data(startup().substr(0, 4));
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, true));
  EXPECT_EQ(0, data.length());
}

TEST_F(PostgresRbacTest, EmptyRulesDeny) {
  rules("{}");
  expectDenied();
  Buffer::OwnedImpl data(startup());
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
}

TEST_F(PostgresRbacTest, DenyRulesAllowUnmatchedConnections) {
  rules("action: DENY\npolicies: {}\n");
  Buffer::OwnedImpl data(startup("user\0app\0\0"s));
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(data, false));
  EXPECT_EQ(
      "app",
      metadata().fields().at("startup").struct_value().fields().at("database").string_value());
}

TEST_F(PostgresRbacTest, LogRulesDoNotDeny) {
  rules("action: LOG\npolicies: {}\n");
  Buffer::OwnedImpl data(startup());
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(data, false));
  EXPECT_FALSE(info_.metadata_.filter_metadata()
                   .at("envoy.common")
                   .fields()
                   .at("access_log_hint")
                   .bool_value());
}

TEST_F(PostgresRbacTest, MatchesPeerUriSan) {
  rules(R"EOF(
action: ALLOW
policies:
  client:
    permissions: [{any: true}]
    principals:
    - authenticated:
        principal_name: {exact: "spiffe://example.com/app"}
)EOF");
  auto ssl = std::make_shared<testing::NiceMock<Ssl::MockConnectionInfo>>();
  std::vector<std::string> sans{"spiffe://example.com/app"};
  ON_CALL(connection_, ssl()).WillByDefault(Return(ssl));
  EXPECT_CALL(*ssl, uriSanPeerCertificate()).WillRepeatedly(Return(absl::MakeConstSpan(sans)));
  Buffer::OwnedImpl data(startup());
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(data, false));
  EXPECT_TRUE(metadata().fields().at("startup").struct_value().fields().at("ssl").bool_value());
}

TEST_F(PostgresRbacTest, MissingPeerIdentityIsDenied) {
  rules(R"EOF(
action: ALLOW
policies:
  client:
    permissions: [{any: true}]
    principals:
    - authenticated:
        principal_name: {exact: "spiffe://example.com/app"}
)EOF");
  auto ssl = std::make_shared<testing::NiceMock<Ssl::MockConnectionInfo>>();
  ON_CALL(connection_, ssl()).WillByDefault(Return(ssl));
  const std::string empty_subject;
  EXPECT_CALL(*ssl, subjectPeerCertificate()).WillOnce(ReturnRef(empty_subject));
  expectDenied();
  Buffer::OwnedImpl data(startup());
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
}

TEST_F(PostgresRbacTest, RequiredTlsRejectsPlaintextEvenWithAllowingRules) {
  rules(BillingRules);
  config_->downstream_ssl_ =
      envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::REQUIRE;
  expectDenied();
  Buffer::OwnedImpl data(startup());
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
  EXPECT_EQ(0, config_->stats_.authorization_allowed_.value());
}

TEST_F(PostgresRbacTest, EmptyDatabaseDefaultsToUser) {
  rules("action: DENY\npolicies: {}\n");
  Buffer::OwnedImpl data(startup("user\0app\0database\0\0\0"s));
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(data, false));
  EXPECT_EQ(
      "app",
      metadata().fields().at("startup").struct_value().fields().at("database").string_value());
}

TEST_F(PostgresRbacTest, RejectsEncryptedPassthrough) {
  rules(BillingRules);
  expectDenied();
  Buffer::OwnedImpl data;
  data.writeBEInt<uint32_t>(8);
  data.writeBEInt<uint32_t>(Postgres::Protocol::SSL_REQUEST_CODE);
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
  EXPECT_EQ(0, data.length());
}

TEST_F(PostgresRbacTest, CoalescedQueryDoesNotReauthorizeOrReplaceStartupMetadata) {
  rules(BillingRules);
  config_->enable_sql_parsing_ = true;
  const std::string query = "select * from startup";
  Buffer::OwnedImpl data(startup());
  data.add("Q");
  data.writeBEInt<uint32_t>(5 + query.size());
  data.add(query);
  data.writeBEInt<uint8_t>(0);
  const std::string bytes = data.toString();
  EXPECT_EQ(Network::FilterStatus::Continue, filter_->onData(data, false));
  EXPECT_EQ(bytes, data.toString());
  EXPECT_EQ(1, config_->stats_.authorization_allowed_.value());
  EXPECT_EQ(1, config_->stats_.statements_parsed_.value());
  EXPECT_EQ("app",
            metadata().fields().at("startup").struct_value().fields().at("user").string_value());
}

class UnsupportedPostgresRequestTest : public PostgresRbacTest,
                                       public testing::WithParamInterface<uint32_t> {};

TEST_P(UnsupportedPostgresRequestTest, RejectsBeforeForwarding) {
  rules("action: DENY\npolicies: {}\n");
  expectDenied();
  Buffer::OwnedImpl data;
  data.writeBEInt<uint32_t>(8);
  data.writeBEInt<uint32_t>(GetParam());
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
  EXPECT_EQ(0, data.length());
}

INSTANTIATE_TEST_SUITE_P(Codes, UnsupportedPostgresRequestTest,
                         testing::Values(Postgres::Protocol::CANCEL_REQUEST_CODE,
                                         Postgres::Protocol::GSSAPI_ENC_REQUEST_CODE, 0x00030001U));

class InvalidPostgresLengthTest : public PostgresRbacTest,
                                  public testing::WithParamInterface<uint32_t> {};

TEST_P(InvalidPostgresLengthTest, RejectsBeforeBuffering) {
  rules("action: DENY\npolicies: {}\n");
  expectDenied();
  Buffer::OwnedImpl data;
  data.writeBEInt<uint32_t>(GetParam());
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
  EXPECT_EQ(0, data.length());
}

INSTANTIATE_TEST_SUITE_P(Lengths, InvalidPostgresLengthTest,
                         testing::Values(0U, 3U, 7U, 10001U, 0xffffffffU));

class InvalidPostgresStartupTest : public PostgresRbacTest,
                                   public testing::WithParamInterface<std::string> {};

TEST_P(InvalidPostgresStartupTest, RejectsInvalidAttributes) {
  rules("action: DENY\npolicies: {}\n");
  expectDenied();
  Buffer::OwnedImpl data(startup(GetParam()));
  EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onData(data, false));
  EXPECT_EQ(0, data.length());
}

INSTANTIATE_TEST_SUITE_P(Attributes, InvalidPostgresStartupTest,
                         testing::Values("user\0app\0"s, "user"s, "user\0app"s,
                                         "database\0billing\0\0"s, "user\0\0\0"s,
                                         "user\0app\0user\0other\0\0"s,
                                         "user\0app\0replication\0true\0\0"s,
                                         "user\0app\0\0trailing"s));

} // namespace
} // namespace PostgresProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
