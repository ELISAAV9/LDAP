import os

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from ldap3 import Server, Connection, ALL

app = FastAPI(
    title="LDAP Authentication API",
    description="Educational FastAPI + OpenLDAP example",
    version="1.0.0",
)

LDAP_HOST = os.getenv("LDAP_HOST", "openldap")
LDAP_PORT = int(os.getenv("LDAP_PORT", "389"))
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")
LDAP_API_KEY = os.getenv("LDAP_API_KEY", "")


def verify_api_key(x_api_key: str = Header(None)):
    if not LDAP_API_KEY or x_api_key != LDAP_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(request: LoginRequest, _auth=Header(default=None, alias="X-API-Key")):
    verify_api_key(_auth)

    server = Server(
        LDAP_HOST,
        port=LDAP_PORT,
        get_info=ALL,
    )

    user_dn = (
        f"uid={request.username},"
        f"ou=users,"
        f"{LDAP_BASE_DN}"
    )

    connection = Connection(
        server,
        user=user_dn,
        password=request.password,
        auto_bind=False,
    )

    try:
        if connection.bind():
            return {
                "authenticated": True,
                "username": request.username,
                "dn": user_dn,
            }

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    finally:
        connection.unbind()