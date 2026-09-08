#include "contrib/postgres_proxy/filters/network/source/config.h"

#include <format>

#include "source/extensions/filters/common/rbac/engine_impl.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace PostgresProxy {

namespace {

absl::Status validatePermission(const envoy::config::rbac::v3::Permission& permission) {
  if (permission.has_header() || permission.has_url_path() || permission.has_uri_template() ||
      (permission.has_sourced_metadata() &&
       permission.sourced_metadata().metadata_source() == envoy::config::rbac::v3::ROUTE)) {
    return absl::InvalidArgumentError(
        "postgres_proxy RBAC does not support HTTP or route matchers");
  }
  for (const auto& rule : permission.and_rules().rules()) {
    RETURN_IF_NOT_OK(validatePermission(rule));
  }
  for (const auto& rule : permission.or_rules().rules()) {
    RETURN_IF_NOT_OK(validatePermission(rule));
  }
  if (permission.has_not_rule()) {
    RETURN_IF_NOT_OK(validatePermission(permission.not_rule()));
  }
  return absl::OkStatus();
}

absl::Status validatePrincipal(const envoy::config::rbac::v3::Principal& principal) {
  if (principal.has_header() || principal.has_url_path() ||
      (principal.has_sourced_metadata() &&
       principal.sourced_metadata().metadata_source() == envoy::config::rbac::v3::ROUTE)) {
    return absl::InvalidArgumentError(
        "postgres_proxy RBAC does not support HTTP or route matchers");
  }
  for (const auto& rule : principal.and_ids().ids()) {
    RETURN_IF_NOT_OK(validatePrincipal(rule));
  }
  for (const auto& rule : principal.or_ids().ids()) {
    RETURN_IF_NOT_OK(validatePrincipal(rule));
  }
  if (principal.has_not_id()) {
    RETURN_IF_NOT_OK(validatePrincipal(principal.not_id()));
  }
  return absl::OkStatus();
}

} // namespace

/**
 * Config registration for the Postgres proxy filter. @see NamedNetworkFilterConfigFactory.
 */
absl::StatusOr<Network::FilterFactoryCb>
NetworkFilters::PostgresProxy::PostgresConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy& proto_config,
    Server::Configuration::FactoryContext& context) {
  ASSERT(!proto_config.stat_prefix().empty());

  PostgresFilterConfig::PostgresFilterConfigOptions config_options;
  config_options.stats_prefix_ = std::format("postgres.{}", proto_config.stat_prefix());
  config_options.enable_sql_parsing_ =
      PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, enable_sql_parsing, true);
  config_options.terminate_ssl_ = proto_config.terminate_ssl();
  if (config_options.terminate_ssl_) {
    ENVOY_LOG(info,
              "postgres_proxy: terminate_ssl is deprecated, please use downstream_ssl instead.");
  }
  config_options.upstream_ssl_ = proto_config.upstream_ssl();
  config_options.downstream_ssl_ = proto_config.downstream_ssl();

  PostgresFilterConfigSharedPtr filter_config(
      std::make_shared<PostgresFilterConfig>(config_options, context.scope()));
  if (proto_config.has_rules()) {
    for (const auto& [name, policy] : proto_config.rules().policies()) {
      for (const auto& permission : policy.permissions()) {
        RETURN_IF_NOT_OK(validatePermission(permission));
      }
      for (const auto& principal : policy.principals()) {
        RETURN_IF_NOT_OK(validatePrincipal(principal));
      }
    }
    filter_config->rules_ =
        std::make_unique<Filters::Common::RBAC::RoleBasedAccessControlEngineImpl>(
            proto_config.rules(), context.messageValidationVisitor(),
            context.serverFactoryContext());
  }
  return [filter_config](Network::FilterManager& filter_manager) -> void {
    filter_manager.addFilter(std::make_shared<PostgresFilter>(filter_config));
  };
}

/**
 * Static registration for the Postgres proxy filter. @see RegisterFactory.
 */
REGISTER_FACTORY(PostgresConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace PostgresProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
