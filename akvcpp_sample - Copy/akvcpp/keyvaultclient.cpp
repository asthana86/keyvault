#include "stdafx.h"
#include "keyvaultclient.h"
#include <time.h>
#include <objbase.h>
#include "cpprest/http_client.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"

using namespace utility;

pplx::task<void> keyvaultclient::authenticate(utility::string_t & clientId, utility::string_t & clientSecret, utility::string_t & keyVaultName)
{
	auto impl = this;
	impl->keyVaultName = keyVaultName;

	// make a un-auth'd request to KeyVault to get a response that contains url to IDP
	impl->get_login_url().wait();
	
	// create the oauth2 authentication request and pass the clientId/Secret as app identifiers
	utility::string_t url = impl->loginUrl + _XPLATSTR("/oauth2/token");
	web::http::client::http_client client(url);
	utility::string_t postData = _XPLATSTR("resource=") + web::uri::encode_uri(impl->resourceUrl) + _XPLATSTR("&client_id=") + clientId
		+ _XPLATSTR("&client_secret=") + clientSecret + _XPLATSTR("&grant_type=client_credentials");
	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/x-www-form-urlencoded"));
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("return-client-request-id"), _XPLATSTR("true"));
	request.headers().add(_XPLATSTR("client-request-id"), get_newguid());
	request.set_body(postData);
	// response from IDP is a JWT Token that contains the token type and access token we need for
	// Azure HTTP REST API calls
	return client.request(request).then([impl](web::http::http_response response)
	{
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			utility::string_t target = impl->read_response_body(response);
			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);
			if (err.value() == 0) {
				impl->tokenType = jwtToken[_XPLATSTR("token_type")].as_string();
				impl->accessToken = jwtToken[_XPLATSTR("access_token")].as_string();
			}
		}
	});
}

bool keyvaultclient::getSecretValue(utility::string_t secretName, web::json::value & secret)
{
	get_secret(secretName).wait();
	secret = this->secret;
	return this->status_code == 200;
}

keyvaultclient::keyvaultclient()
{
}


keyvaultclient::~keyvaultclient()
{
}

string_t keyvaultclient::get_https_url(utility::string_t headerValue)
{
	size_t pos1 = headerValue.find(_XPLATSTR("https://"));
	if (pos1 >= 0) {
		size_t pos2 = headerValue.find(_XPLATSTR("\""), pos1 + 1);
		if (pos2 > pos1) {
			utility::string_t url = headerValue.substr(pos1, pos2 - pos1);
			headerValue = url;
		}
		else {
			utility::string_t url = headerValue.substr(pos1);
			headerValue = url;
		}
	}
	return headerValue;
}

pplx::task<void> keyvaultclient::get_login_url()
{
	auto impl = this;
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/secretname?api-version=2015-06-01");
	web::http::client::http_client client(url);
	return client.request(web::http::methods::GET).then([impl](web::http::http_response response)
	{
		impl->status_code = response.status_code();
		if (impl->status_code == 401) {
			web::http::http_headers& headers = response.headers();
			impl->keyVaultRegion = headers[_XPLATSTR("x-ms-keyvault-region")];
			const utility::string_t& wwwAuth = headers[_XPLATSTR("WWW-Authenticate")];
			// parse WWW-Authenticate header into url links. Format:
			// Bearer authenticate="url", resource="url"
			utility::string_t delimiter = _XPLATSTR(" ");
			size_t count = 0, start = 0, end = wwwAuth.find(delimiter);
			while (end != utility::string_t::npos)
			{
				utility::string_t part = wwwAuth.substr(start, end - start);
				if (count == 1) {
					impl->loginUrl = impl->get_https_url(part);
				}
				start = end + delimiter.length();
				end = wwwAuth.find(delimiter, start);
				count++;
			}
			utility::string_t part = wwwAuth.substr(start, end - start);
			impl->resourceUrl = impl->get_https_url(part);
		}
	});
}

pplx::task<void> keyvaultclient::get_secret(utility::string_t secretName)
{
	auto impl = this;
	// create the url path to query the keyvault secret
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/") + secretName + _XPLATSTR("?api-version=2015-06-01");
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), get_newguid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			utility::string_t target = impl->read_response_body(response);
			impl->secret = web::json::value::parse(target.c_str(), err);
		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}

string_t keyvaultclient::get_newguid()
{
string_t guid;
#ifdef _WIN32
	GUID wguid;
	::CoCreateGuid(&wguid);
	wchar_t		uuid_str[38 + 1];
	::StringFromGUID2((const GUID&)wguid, uuid_str, sizeof(uuid_str));
#else
	uuid_t uuid;
	uuid_generate_time_safe(uuid);
	char uuid_str[37];
	uuid_unparse_lower(uuid, uuid_str);
#endif
	guid = uuid_str;
	return guid;
}

string_t keyvaultclient::read_response_body(web::http::http_response response)
{
	auto bodyStream = response.body();
	concurrency::streams::stringstreambuf sb;
	auto& target = sb.collection();
	bodyStream.read_to_end(sb).get();
#ifdef _WIN32 // Windows uses UNICODE but result is in UTF8, so we need to convert it
	utility::string_t wtarget;
	wtarget.assign(target.begin(), target.end());
	return wtarget;
#else
	return target;
#endif
}
