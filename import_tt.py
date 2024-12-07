# BM 20241207
import requests
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta
import logging

# Global Configuration
TRAKT_API_URL = "https://api.trakt.tv"
TOKEN_URL = f"{TRAKT_API_URL}/oauth/token"
AUTH_URL = f"{TRAKT_API_URL}/oauth/authorize"
CLIENT_ID = "<CLIENT_ID>"
CLIENT_SECRET = "<CLIENT_SECRET>"
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"  # Redirect used for CLI script
TOKEN_FILE = "trakt_token.json"

# HTTP Headers Configuration
HEADERS = {
    "Content-Type": "application/json",
    "trakt-api-version": "2",
    "trakt-api-key": CLIENT_ID
}

# Logging Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def save_token(token_data):
    """Save the token to a JSON file with its expiration date."""
    token_data["expires_at"] = (datetime.now() + timedelta(seconds=token_data["expires_in"])).isoformat()
    with open(TOKEN_FILE, "w", encoding="utf-8") as file:
        json.dump(token_data, file, indent=4)
    logger.info("Token saved to trakt_token.json.")


def load_token():
    """Load the token from the file, if it exists and is still valid."""
    if not Path(TOKEN_FILE).exists():
        return None
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as file:
            token_data = json.load(file)

        # Check if the token is still valid
        if datetime.fromisoformat(token_data["expires_at"]) > datetime.now():
            logger.info("Token loaded from file.")
            return token_data["access_token"]

        logger.warning("Token expired, re-authentication required.")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error loading token: {e}")
        return None


def get_token(grant_type, auth_code=None):
    """Retrieve a Bearer Token via OAuth 2.0 (Client Credentials or Authorization Code Grant)."""
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": grant_type,
        "redirect_uri": REDIRECT_URI
    }

    if grant_type == "authorization_code" and auth_code:
        payload["code"] = auth_code

    response = requests.post(TOKEN_URL, json=payload)
    if response.status_code == 200:
        token_data = response.json()
        save_token(token_data)
        logger.info(f"Token ({grant_type}) retrieved successfully.")
        return token_data["access_token"]
    else:
        logger.error(f"Error retrieving token: {response.status_code} - {response.text}")
        return None


def add_to_watchlist(imdb_ids, access_token, item_type):
    """Add movies or shows identified by their IMDb IDs to the Trakt watchlist."""
    url = f"{TRAKT_API_URL}/sync/watchlist"
    
    if item_type == "movies":
        payload = {"movies": [{"ids": {"imdb": imdb_id}} for imdb_id in imdb_ids]}
    elif item_type == "shows":
        payload = {"shows": [{"ids": {"imdb": imdb_id}} for imdb_id in imdb_ids]}
    
    headers = {**HEADERS, "Authorization": f"Bearer {access_token}"}

    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 201:
        logger.info(f"Success: {response.json()}")
    else:
        logger.error(f"Error ({response.status_code}): {response.text}")


def read_ids_from_file(file_path):
    """Read IMDb IDs from a JSON file and filter out invalid IDs."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        # Filter valid IDs (non-empty)
        imdb_ids = [entry["id"] for entry in data if "id" in entry and entry["id"].strip()]
        invalid_ids = [entry for entry in data if not entry.get("id") or not entry["id"].strip()]

        if invalid_ids:
            logger.warning(f"{len(invalid_ids)} entries with invalid IDs were ignored.")

        return imdb_ids
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Add movies or shows to the Trakt watchlist.")
    parser.add_argument("file", help="Path to the file containing IMDb IDs.")
    parser.add_argument(
        "--auth-method", 
        choices=["client_credentials", "authorization_code"], 
        default="authorization_code",  # Changed here, default method is authorization_code
        help="Authentication method to use."
    )
    parser.add_argument(
        "--movies", 
        action="store_true", 
        help="Indicate that the IDs in the file are movies."
    )
    parser.add_argument(
        "--shows", 
        action="store_true", 
        help="Indicate that the IDs in the file are shows."
    )

    # Handle invalid arguments
    try:
        args = parser.parse_args()
    except SystemExit as e:
        parser.print_help()  # Display expected arguments in case of error
        return

    # Check that the user has selected either movies or shows
    if not (args.movies or args.shows):
        logger.error("You must specify either --movies or --shows.")
        parser.print_help()  # Show help if argument is missing
        return

    item_type = "movies" if args.movies else "shows"

    # Read IMDb IDs
    file_path = Path(args.file)
    if not file_path.exists():
        logger.error("File not found.")
        return

    imdb_ids = read_ids_from_file(file_path)
    if not imdb_ids:
        logger.error("No valid IMDb IDs found.")
        return

    # Load token if available
    access_token = load_token()
    if not access_token:
        # Retrieve the access token
        if args.auth_method == "client_credentials":
            access_token = get_token("client_credentials")
        else:
            auth_code = input("Paste the authorization code obtained: ").strip()
            access_token = get_token("authorization_code", auth_code)

    if not access_token:
        logger.error("Unable to retrieve Bearer Token. Stopping.")
        return

    # Add IDs to the watchlist
    logger.info(f"Adding {len(imdb_ids)} {item_type} to the watchlist...")
    add_to_watchlist(imdb_ids, access_token, item_type)


if __name__ == "__main__":
    main()
