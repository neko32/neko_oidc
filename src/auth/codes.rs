use chrono::prelude::*;
use rand::prelude::*;
use sqlx::PgPool;
use uuid::Uuid;

/// 30文字の英数字からなる認可コード文字列を生成する（DB 非依存・テスト可能）。
pub fn generate_auth_code() -> String {
    let mut rng = rand::rng();
    (0..30)
        .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
        .collect::<String>()
}

#[async_trait::async_trait]
pub trait AuthCodeStore {
    async fn insert_auth_code(
        &self, 
        client_id: &str, 
        user_id: &Uuid, 
        redirect_uris: &str) -> Result<String, sqlx::Error>;
}

pub struct PgAuthCodeStore(pub PgPool);

/// DB に認可コードを保存してコード文字列を返す。

#[async_trait::async_trait]
impl AuthCodeStore for PgAuthCodeStore {
    async fn insert_auth_code(
        &self,
        client_id: &str, 
        user_id: &Uuid, 
        redirect_uris: &str) -> Result<String, sqlx::Error> {
        let code = generate_auth_code();
        let expires_at = Local::now() + chrono::Duration::minutes(10);
        let query = "INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, expires_at) VALUES ($1, $2, $3, $4, $5)";
        let rez = sqlx::query(query)
            .bind(&code)
            .bind(client_id)
            .bind(user_id)
            .bind(redirect_uris)
            .bind(expires_at)
            .execute(&self.0)
            .await?;
        return if rez.rows_affected() == 1 { Ok(code) } else { Err(sqlx::Error::RowNotFound) }
    }
}

#[cfg(test)]
struct MockAuthCodeStore;

#[cfg(test)]
#[async_trait::async_trait]
impl AuthCodeStore for MockAuthCodeStore {
    async fn insert_auth_code(
        &self, 
        _client_id: &str, 
        _user_id: &Uuid, 
        _redirect_uris: &str) -> Result<String, sqlx::Error> {
        Ok("MOCKMOCK".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_auth_code_has_length_30() {
        let code = generate_auth_code();
        assert_eq!(code.len(), 30, "認可コードは30文字であること");
    }

    #[test]
    fn generate_auth_code_is_alphanumeric() {
        let code = generate_auth_code();
        assert!(code.chars().all(|c| c.is_ascii_alphanumeric()), "認可コードは英数字のみであること");
    }

    #[test]
    fn generate_auth_code_differ_each_call() {
        let a = generate_auth_code();
        let b = generate_auth_code();
        // ランダムなので同じになる確率は極めて低い（念のため複数回生成の差があることを確認）
        assert_ne!(a, b, "呼び出しごとに異なるコードが生成されること");
    }

    #[tokio::test]
    async fn insert_auth_code_should_succeed_with_mock_store() {
        let store = MockAuthCodeStore;
        let client_id = "test_client_id";
        let user_id = Uuid::new_v4();
        let redirect_uris = "test_redirect_uris";
        let result = store.insert_auth_code(client_id, &user_id, redirect_uris).await;
        assert!(result.is_ok(), "認可コードの保存に成功すること");
    }
}
