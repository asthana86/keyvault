#pragma once
#include "was/storage_account.h"
#include "was/blob.h"
#include "cpprest/http_client.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"

using namespace utility;

class keyvaultclient
{
public:
	string_t tokenType;
    string_t accessToken;
	string_t keyVaultUrl;
	string_t loginUrl;
	string_t resourceUrl;
	string_t keyVaultName;
	string_t keyVaultRegion;
	pplx::task<void> authenticate(utility::string_t& clientId, utility::string_t& clientSecret, utility::string_t& keyVaultName);
	bool getSecretValue(utility::string_t secretName, web::json::value& secret);
	keyvaultclient();
	~keyvaultclient();

private:
	int status_code;
	web::json::value secret;
	utility::string_t get_https_url(utility::string_t headerValue);
	pplx::task<void>  get_login_url();
	pplx::task<void>  get_secret(utility::string_t secretName);
	utility::string_t get_newguid();
	utility::string_t read_response_body(web::http::http_response response);
};

