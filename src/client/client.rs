use chrono::prelude::*;
use sqlx::PgPool;
use uuid::Uuid;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString}
};
use rand::prelude::*;

fn generate_random_secret() -> String {
    let mut rng = rand::rng();
    (0..32)
        .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
        .collect()
}

#[async_trait::async_trait]
pub trait ClientStore {
    async fn register_client(
        &self, 
        client_name: &str, 
        redirect_uris: Vec<&str>, 
        grant_types: Vec<&str>) -> Result<String, sqlx::Error>;
}

pub struct PgClientStore(pub PgPool);

#[async_trait::async_trait]
impl ClientStore for PgClientStore {
    async fn register_client(
        &self, 
        client_name: &str,
        redirect_uris: Vec<&str>, 
        grant_types: Vec<&str>) -> Result<String, sqlx::Error> {
        let query = "INSERT INTO oidc_clients (client_id, client_name, client_secret_hash, redirect_uris, grant_types, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)";
        let client_id = Uuid::new_v4();
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = argon2::Argon2::default();
        let secret = generate_random_secret();
        let client_secret = argon2.hash_password(secret.as_bytes(), &salt).expect("Failed to hash password").to_string();
        let created_at = Local::now();
        let updated_at = Local::now();

        let rez = sqlx::query(query)
            .bind(client_id)
            .bind(client_name)
            .bind(client_secret)
            .bind(redirect_uris)
            .bind(grant_types)
            .bind(created_at)
            .bind(updated_at)
            .execute(&self.0)
            .await?;
        return if rez.rows_affected() == 1 { Ok(secret) } else { Err(sqlx::Error::RowNotFound) }
    }
}

#[cfg(test)]
struct MockClientStore;

#[cfg(test)]
#[async_trait::async_trait]
impl ClientStore for MockClientStore {
    async fn register_client(
        &self,
        _client_name: &str,
        _redirect_uris: Vec<&str>,
        _grant_types: Vec<&str>) -> Result<String, sqlx::Error> {
        Ok("MOCKMOCK".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_client_should_succeed_with_mock_store() {
        let store = MockClientStore;
        let client_name = "test_client";
        let redirect_uris = vec!["http://localhost:18080/callback"];
        let grant_types = vec!["authorization_code"];
        let result = store.register_client(client_name, redirect_uris, grant_types).await;
        assert!(result.is_ok(), "register_client should succeed: {:?}", result);
        let secret = result.unwrap();
        assert_eq!(secret, "MOCKMOCK");
    }
}
