#pragma once
#include "servererror/servererror.h"
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/fields_fwd.hpp>
#include <boost/beast/http/message_fwd.hpp>
#include <boost/json/fwd.hpp>
#include <boost/json/object.hpp>
#include <chrono>
#include <iostream>
#include <iterator>
#include <jwt-cpp/base.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/boost-json/traits.h>
#include <optional>
#include <ranges>
#include <string_view>
#include <system_error>

namespace Security {

inline std::string createJwt(boost::json::object payload,
                             std::chrono::system_clock::time_point expireAt,
                             std::string_view jwtType, std::string_view issuer,
                             std::string_view payloadKey,
                             std::string_view secreteKey) {
  auto token = jwt::create<jwt::traits::boost_json>(jwt::default_clock{})
                   .set_type(jwtType.data())
                   .set_issuer(issuer.data())
                   .set_payload_claim(payloadKey.data(), payload)
                   .set_expires_at(expireAt)
                   .sign(jwt::algorithm::hs256{secreteKey.data()});
  return token;
}

template <typename Body, typename Allocator>
inline std::optional<boost::json::value>
verifyJwt(boost::beast::http::request<
              Body, boost::beast::http::basic_fields<Allocator>> &request,
          std::string_view jwtType, std::string_view issuer,
          std::string_view payloadKey, const std::string &secret,
          std::error_code &ec) {
  std::string bearer = request[boost::beast::http::field::authorization];

  if (bearer.empty()) {
    ec = ServerError::Unauthorize_Access;
    return std::nullopt;
  }
  auto parts = bearer | std::ranges::views::split(' ');

  if (std::ranges::distance(parts) != 2) {
    ec = ServerError::Unauthorize_Access;
    return std::nullopt;
  }

  auto it = parts.begin();
  auto bearerIt = std::ranges::next(it, 1);

  std::string_view token(*bearerIt);

  try {

    auto decoded_token = jwt::decode<jwt::traits::boost_json>(token.data());
    auto verifier = jwt::verify<jwt::traits::boost_json>()
                        .with_issuer(issuer.data())
                        .with_type(jwtType.data())
                        .allow_algorithm(jwt::algorithm::hs256{secret})
                        .expires_at_leeway(0);

    verifier.verify(decoded_token, ec);

    if (ec) {
      std::cout << ec.message() << std::endl;
      if (ec == jwt::error::token_verification_error::token_expired) {
        ec = ServerError::AccessToken_Expired;
        return std::nullopt;
      }
      ec = ServerError::Invalid_AcessToken;
      return std::nullopt;
    }

    auto val = decoded_token.get_payload_claim(payloadKey.data()).to_json();

    return val;
  } catch (const std::exception &ec) {
  };

  ec = ServerError::Invalid_AcessToken;

  return std::nullopt;
};

}; // namespace Security