import argparse
from bcrypt import hashpw, gensalt
import os
from os import getenv
import psycopg as pg
import uuid

VALID_GRANT_TYPES = ["authorization_code", "refresh_token"]

def validate(client_id: str, client_name: str, redirect_uris: list[str], grant_types: list[str]) -> bool:
    if not client_id:
        return False
    if len(client_name) > 100:
        return False
    if len(redirect_uris) > 100:
        return False
    for uri in redirect_uris:
        if len(uri) > 2000:
            return False
        # Check if it's a valid URL
        from urllib.parse import urlparse
        parsed = urlparse(uri)
        if not (parsed.scheme in ("http", "https") and parsed.netloc):
            return False
    if len(grant_types) > 100 or not all(grant_type in VALID_GRANT_TYPES for grant_type in grant_types):
        return False
    return True

def gen_client_secret() -> str:
    return hashpw(os.urandom(32), gensalt()).decode("utf-8")

def register_client_to_db(client_id: str, client_name: str, client_secret: str, redirect_uris: list[str], grant_types: list[str]) -> bool:
    try:
        db_host = getenv("NEKOXDB_HOST")
        db_port = getenv("NEKOXDB_PORT")
        db_user = getenv("NEKOXDB_USER")
        db_passwd = getenv("NEKOXDB_PASSWD")
        db_url = f"postgresql://{db_user}:{db_passwd}@{db_host}:{db_port}/neko_ident"
        conn = pg.connect(db_url)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO oidc_clients (client_id, client_name, client_secret_hash, redirect_uris, grant_types) VALUES (%s, %s, %s, %s, %s)", (client_id, client_name, client_secret, redirect_uris, grant_types))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-name", type=str, required=True)
    parser.add_argument("--redirect-uris", type=str, required=True)
    parser.add_argument("--grant-types", type=str, required=True)
    args = parser.parse_args()
    client_id = str(uuid.uuid4())
    client_name = args.client_name
    redirect_uris = args.redirect_uris.split(",")
    grant_types = args.grant_types.split(",")
    client_secret = gen_client_secret()

    if not validate(client_id, client_name, redirect_uris, grant_types):
        print("Invalid input")
        return
    
    print(f"Client ID: {client_id}")
    print(f"Client Name: {client_name}")
    print(f"Redirect URIs: {redirect_uris}")
    print(f"Grant Types: {grant_types}")
    print(f"Client Secret: {('*' * len(client_secret))}")

    try:
        if not register_client_to_db(client_id, client_name, client_secret, redirect_uris, grant_types):
            print("Failed to register client to database")
            return
        print(f"Client {client_id}({client_name}) registered to database successfully")
        return

    except Exception as e:
        print(f"Error: {e}")
        return






if __name__ == "__main__":
    main()