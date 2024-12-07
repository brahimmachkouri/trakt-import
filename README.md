## IMDb to Trakt Watchlist Import Script
### Description

This script imports a list of IMDb IDs from a JSON file and adds them to the user's Trakt watchlist via the Trakt API. It handles authentication using OAuth 2.0 and ensures valid IDs are processed efficiently.

---

### Features

- Read IMDb IDs from a JSON file:
    The script reads IMDb IDs from a JSON file in the following format:
    ```json
    [
        { "id": "tt1375666" },
        { "id": "tt0133093" },
        { "id": "tt0111161" }
    ]
    ```

- OAuth 2.0 Authentication:
    - Client Credentials Grant: For general actions without user-specific authorization.
    - Authorization Code Grant: Requires explicit user authorization.
    - Token management:
        - Saves the OAuth token in a trakt_token.json file to avoid repeated authentications.
        - Checks token validity before reuse, ensuring minimal interruptions.
    - Add IMDb IDs to the Trakt watchlist:
        Valid IDs are sent in batches to the Trakt API for efficient processing.

#### How to Use
1. Configure Trakt credentials

    - Obtain a Client ID and Client Secret from [Trakt Developer](https://trakt.tv/oauth/applications).
    - Replace <CLIENT_ID> and <CLIENT_SECRET> in the script with your credentials.

2. Create a JSON file with IMDb IDs (cf above)
3. Run the script :

Using Authorization Code Grant (requires user login):
```bash
python script.py imdb_ids.json
```
<!-- 
Using Client Credentials Grant (no user login required):
```bash
python script.py imdb_ids.json --auth-method client_credentials
```
-->
### Results
- IMDb IDs are added to your Trakt watchlist.
- OAuth token is saved in trakt_token.json for future use.
