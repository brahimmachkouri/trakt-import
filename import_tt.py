import requests
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta

# Configuration globale
TRAKT_API_URL = "https://api.trakt.tv"
TOKEN_URL = f"{TRAKT_API_URL}/oauth/token"
AUTH_URL = f"{TRAKT_API_URL}/oauth/authorize"
CLIENT_ID = "<CLIENT_ID>"
CLIENT_SECRET = "<CLIENT_SECRET>"
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"  # Redirection utilisée pour un script CLI
TOKEN_FILE = "trakt_token.json"

HEADERS = {
    "Content-Type": "application/json",
    "trakt-api-version": "2",
    "trakt-api-key": CLIENT_ID
}


def save_token(token_data):
    """
    Sauvegarde le token dans un fichier JSON avec sa date d'expiration.
    """
    token_data["expires_at"] = (datetime.now() + timedelta(seconds=token_data["expires_in"])).isoformat()
    with open(TOKEN_FILE, "w", encoding="utf-8") as file:
        json.dump(token_data, file, indent=4)
    print("Token sauvegardé dans trakt_token.json.")


def load_token():
    """
    Charge le token depuis le fichier, s'il existe et s'il est encore valide.
    """
    if not Path(TOKEN_FILE).exists():
        return None
    with open(TOKEN_FILE, "r", encoding="utf-8") as file:
        token_data = json.load(file)

    # Vérifie si le token est encore valide
    if datetime.fromisoformat(token_data["expires_at"]) > datetime.now():
        print("Token chargé depuis le fichier.")
        return token_data["access_token"]
    print("Token expiré, nouvelle authentification requise.")
    return None


def get_token_client_credentials():
    """
    Récupère un Bearer Token via le Client Credentials Grant.
    """
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials"
    }

    response = requests.post(TOKEN_URL, json=payload)
    if response.status_code == 200:
        token_data = response.json()
        save_token(token_data)
        print("Token (Client Credentials) récupéré avec succès.")
        return token_data["access_token"]
    else:
        print(f"Erreur lors de la récupération du token : {response.status_code} - {response.text}")
        return None


def get_token_authorization_code():
    """
    Récupère un Bearer Token via Authorization Code Grant.
    """
    print(f"Ouvrez ce lien dans votre navigateur pour autoriser l'accès :\n")
    print(f"{AUTH_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}\n")
    
    # Demande le code d'autorisation à l'utilisateur
    auth_code = input("Collez ici le code d'autorisation obtenu : ").strip()

    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": auth_code,
        "grant_type": "authorization_code"
    }

    response = requests.post(TOKEN_URL, json=payload)
    if response.status_code == 200:
        token_data = response.json()
        save_token(token_data)
        print("Token (Authorization Code) récupéré avec succès.")
        return token_data["access_token"]
    else:
        print(f"Erreur lors de la récupération du token : {response.status_code} - {response.text}")
        return None


def add_to_watchlist(imdb_ids, access_token):
    """
    Ajoute des films identifiés par leurs IMDb IDs à la watchlist Trakt.
    """
    url = f"{TRAKT_API_URL}/sync/watchlist"
    payload = {"movies": [{"ids": {"imdb": imdb_id}} for imdb_id in imdb_ids]}
    headers = {**HEADERS, "Authorization": f"Bearer {access_token}"}

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 201:
        print(f"Succès : {response.json()}")
    else:
        print(f"Erreur ({response.status_code}) : {response.text}")


def read_ids_from_file(file_path):
    """
    Lit les IDs IMDb à partir d'un fichier JSON et filtre les IDs invalides.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        
        # Filtrer les IDs valides (non vides)
        imdb_ids = [entry["id"] for entry in data if "id" in entry and entry["id"].strip()]
        invalid_ids = [entry for entry in data if not entry.get("id") or not entry["id"].strip()]

        if invalid_ids:
            print(f"Attention : {len(invalid_ids)} entrées avec des IDs invalides ont été ignorées.")

        return imdb_ids
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier : {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Ajoute des films dans la watchlist Trakt.")
    parser.add_argument("file", help="Chemin du fichier contenant les IDs IMDb.")
    parser.add_argument(
        "--auth-method", 
        choices=["client_credentials", "authorization_code"], 
        default="authorization_code", 
        help="Méthode d'authentification à utiliser."
    )
    args = parser.parse_args()

    # Lecture des IMDb IDs
    file_path = Path(args.file)
    if not file_path.exists():
        print("Fichier introuvable.")
        return

    imdb_ids = read_ids_from_file(file_path)
    if not imdb_ids:
        print("Aucun ID IMDb valide trouvé.")
        return

    # Charger le token si disponible
    access_token = load_token()
    if not access_token:
        # Récupération du token d'accès
        if args.auth_method == "client_credentials":
            access_token = get_token_client_credentials()
        else:
            access_token = get_token_authorization_code()

    if not access_token:
        print("Impossible de récupérer un Bearer Token. Arrêt.")
        return

    # Ajout des IDs à la watchlist
    print(f"Ajout de {len(imdb_ids)} films à la watchlist...")
    add_to_watchlist(imdb_ids, access_token)


if __name__ == "__main__":
    main()
