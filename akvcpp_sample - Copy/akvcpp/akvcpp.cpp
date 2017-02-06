#include "stdafx.h"
#include "keyvaultclient.h"

#include <time.h>
#include <objbase.h>

#include "cpprest/http_client.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"

using namespace utility;
using namespace std;
using namespace web::json;

string_t clientId = _XPLATSTR("");
string_t clientSecret = _XPLATSTR("");
string_t keyVaultName = _XPLATSTR("");
string_t blobContainer = _XPLATSTR("");
bool verbose = false;

void GetConfig(utility::string_t configFile)
{
	utility::ifstream_t fin(configFile);
	utility::string_t line;
	utility::istringstream_t sin;
	utility::string_t val;

	while (std::getline(fin, line)) {
		sin.str(line.substr(line.find(_XPLATSTR("=")) + 1));
		sin >> val;
		if (line.find(_XPLATSTR("keyVaultName")) != std::string::npos) {
			keyVaultName = val;
		}
		else if (line.find(_XPLATSTR("clientId")) != std::string::npos) {
			clientId = val;
		}
		else if (line.find(_XPLATSTR("clientSecret")) != std::string::npos) {
			clientSecret = val;
		}
		else if (line.find(_XPLATSTR("blobContainer")) != std::string::npos) {
			blobContainer = val;
		}
		else if (line.find(_XPLATSTR("verbose")) != std::string::npos) {
			if (val.find(_XPLATSTR("true")) != std::string::npos) {
				verbose = true;
			}
		}
		sin.clear();
	}
}

int main(int argc, wchar_t* argv[])
{
	if (argc < 2) {
		wcout << _XPLATSTR("syntax: azkvault secretname") << std::endl;
	}
	keyvaultclient kvc;
	string_t secretName = L"language";
	string_t fileName = _XPLATSTR("");
	string_t blobName = _XPLATSTR("");

	if (argc >= 4) {
		fileName = argv[2];
		blobName = argv[3];
	}

	GetConfig(_XPLATSTR("akvcppvault.conf"));

	wcout << _XPLATSTR("Authenticating for KeyVault ") << keyVaultName.c_str() << _XPLATSTR("...") << std::endl;
	wcout << _XPLATSTR("clientId : ") << clientId.c_str() << _XPLATSTR("...") << std::endl;

	kvc.authenticate(clientId, clientSecret, keyVaultName).wait();

	if (verbose) {
		wcout << _XPLATSTR("Azure Region: ") << kvc.keyVaultRegion.c_str() << std::endl;
		wcout << _XPLATSTR("ResourceUrl : ") << kvc.resourceUrl.c_str() << std::endl;
		wcout << _XPLATSTR("LoginUrl    : ") << kvc.loginUrl.c_str() << std::endl;
		wcout << kvc.tokenType.c_str() << _XPLATSTR(" ") << kvc.accessToken.c_str() << std::endl;
	}

	wcout << _XPLATSTR("Querying KeyVault Secret ") << secretName.c_str() << _XPLATSTR("...") << std::endl;
	value jsonSecret;

	bool rc = kvc.getSecretValue(secretName, jsonSecret);

	if (rc == false) {
		wcout << _XPLATSTR("Secret doesn't exist") << std::endl;
		return 1;
	}
	wcout << _XPLATSTR("Secret ID   : ") << jsonSecret[_XPLATSTR("id")].as_string().c_str() << std::endl;
	wcout << _XPLATSTR("Secret Value: ") << jsonSecret[_XPLATSTR("value")].as_string().c_str() << std::endl;
	return 0;
}

