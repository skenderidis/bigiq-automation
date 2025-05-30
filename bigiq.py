import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
BIGIQ_HOST = "https://ed2cccee-b8cb-49a5-8cf1-c198f046b106.access.udf.f5.com"
USERNAME = "admin"
PASSWORD = "admin.F5demo.com"

# --- Authenticate ---
def get_token():
    url = f"{BIGIQ_HOST}/mgmt/shared/authn/login"
    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "loginProviderName": "tmos"
    }
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()["token"]["token"]

# --- Get All Virtual Servers ---
def get_virtual_servers(token):
    url = f"{BIGIQ_HOST}/mgmt/cm/adc-core/working-config/ltm/virtual"
    headers = {"X-F5-Auth-Token": token}
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

# --- Get clientssl profiles from profiles reference ---
def get_clientssl_profiles(token, profiles_url):
    if profiles_url.startswith("https://localhost"):
        profiles_url = profiles_url.replace("https://localhost", BIGIQ_HOST)
    
    headers = {"X-F5-Auth-Token": token}
    response = requests.get(profiles_url, headers=headers, verify=False)
    response.raise_for_status()
    profiles = response.json().get("items", [])
    
    return [
        {
            "name": p.get("name", "Unknown"),
            "clientssl_link": p.get("profileClientsslReference", {}).get("link")
        }
        for p in profiles if "profileClientsslReference" in p
    ]

# --- Get cert and key from clientssl profile ---
def get_cert_key_from_clientssl(token, clientssl_link):
    if clientssl_link.startswith("https://localhost"):
        clientssl_link = clientssl_link.replace("https://localhost", BIGIQ_HOST)

    headers = {"X-F5-Auth-Token": token}
    response = requests.get(clientssl_link, headers=headers, verify=False)
    if not response.ok:
        return ("[error]", "[error]")

    data = response.json()
    cert_key_chain = data.get("certKeyChain", [])
    if not cert_key_chain:
        return ("[missing]", "[missing]")

    chain_entry = cert_key_chain[0]  # Get the first certKeyChain entry
    cert = chain_entry.get("certReference", {}).get("name", "[missing]")
    key = chain_entry.get("keyReference", {}).get("name", "[missing]")
    return cert, key
# --- Main ---
if __name__ == "__main__":
    try:
        token = get_token()
        virtual_servers = get_virtual_servers(token)

        print(f"\nTotal Virtual Servers: {len(virtual_servers)}\n")

        for vs in virtual_servers:
            name = vs.get("name")
            partition = vs.get("partition")
            full_path = f"/{partition}/{name}"
            profiles_link = vs.get("profilesCollectionReference", {}).get("link")
            device_name = vs.get("deviceReference", {}).get("name", "[unknown-device]")

            print(f"Virtual Server: {full_path}")
            print(f"  Device: {device_name}")

            if not profiles_link:
                print("  - No profiles reference found\n")
                continue

            clientssl_profiles = get_clientssl_profiles(token, profiles_link)
            if not clientssl_profiles:
                print("  - No clientssl profiles found\n")
                continue

            for prof in clientssl_profiles:
                profile_name = prof["name"]
                clientssl_link = prof["clientssl_link"]
                cert, key = get_cert_key_from_clientssl(token, clientssl_link)
                print(f"  - clientssl Profile: {profile_name}")
                print(f"      Certificate: {cert}")
                print(f"      Key        : {key}")
            print("")

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
