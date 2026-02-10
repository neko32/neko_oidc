CREATE TABLE oidc_clients (
    -- クライアントID（ランダムな文字列）
    client_id VARCHAR(50) PRIMARY KEY,
    
    -- クライアント・シークレット（ハッシュ化して保存される）
    client_secret_hash VARCHAR(255) NOT NULL,
    
    -- クライアント名（表示用）
    client_name VARCHAR(100) NOT NULL,
    
    -- 許可されたリダイレクトURI（カンマ区切り、または別テーブルで管理）
    redirect_uris TEXT NOT NULL,
    
    -- 許可されたフロー（例: 'authorization_code', 'refresh_token'）
    grant_types VARCHAR(100) DEFAULT 'authorization_code',
    
    -- 作成日時と更新日時
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
