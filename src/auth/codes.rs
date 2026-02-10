use sqlx::PgPool;
use chrono::prelude::*;
use rand::prelude::*;
use uuid::Uuid;

pub async fn issue_code(pool: &PgPool, client_id: &str, user_id: &Uuid, redirect_uris: &str) -> Result<String, sqlx::Error> {
    let mut rng = rand::rng();
    let code = (0..30)
        .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
        .collect::<String>();
    let expires_at = Local::now() + chrono::Duration::minutes(10);
    let query = "INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, expires_at) VALUES ($1, $2, $3, $4, $5)";
    sqlx::query(query)
        .bind(&code)
        .bind(client_id)
        .bind(user_id)
        .bind(redirect_uris)
        .bind(expires_at)
        .execute(pool)
        .await?;
    Ok(code)
}