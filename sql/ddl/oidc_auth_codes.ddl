CREATE TABLE oidc_auth_codes (
    code TEXT PRIMARY KEY,
    client_id VARCHAR(50) NOT NULL,
    user_id UUID NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (client_id) REFERENCES oidc_clients(client_id)
);
