//! 認可コードまわりの統合テスト。
//!
//! - ライブラリの公開 API を通した振る舞いを検証する。
//! - DB 接続が必要なテストは `#[ignore]` 付き。実行時は
//!   `cargo test --test auth_codes_integration -- --include-ignored`
//!   で NEKOXDB_* 環境変数と実 DB を用意してから実行する。

use neko_oidc::auth::codes::{generate_auth_code, AuthCodeStore, PgAuthCodeStore};
use neko_oidc::client::client::{ClientStore, PgClientStore};
use uuid::Uuid;

// ========== DB 不要（常時実行） ==========

#[test]
fn integration_generate_auth_code_via_public_api() {
    let code = generate_auth_code();
    assert_eq!(code.len(), 30);
    assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
}

// ========== DB 接続あり（--include-ignored で実行） ==========

fn test_dsn() -> Option<String> {
    let host = std::env::var("NEKOXDB_HOST").ok()?;
    let port = std::env::var("NEKOXDB_PORT").ok()?;
    let user = std::env::var("NEKOXDB_USER").ok()?;
    let pass = std::env::var("NEKOXDB_PASSWD").ok()?;
    Some(format!(
        "postgres://{}:{}@{}:{}/neko_ident?sslmode=disable",
        user, pass, host, port
    ))
}

#[tokio::test]
#[ignore = "NEKOXDB_* を設定し、Postgres と oidc_auth_codes テーブル・登録済み client_id が必要"]
async fn integration_insert_auth_code_with_real_db() {
    let dsn = match test_dsn() {
        Some(s) => s,
        None => {
            eprintln!("skip: NEKOXDB_* not set");
            return;
        }
    };
    let pool = sqlx::PgPool::connect(&dsn).await.expect("DB connect");
    let store = PgAuthCodeStore(pool);

    // oidc_clients に存在する client_id を使う必要あり（FK 制約）
    let client_id = std::env::var("NEKO_OIDC_TEST_CLIENT_ID").unwrap_or_else(|_| {
        eprintln!("skip: NEKO_OIDC_TEST_CLIENT_ID not set (use existing client_id)");
        String::new()
    });
    if client_id.is_empty() {
        return;
    }

    let user_id = Uuid::new_v4();
    let redirect_uris = "http://localhost:18080/callback";

    let result = store
        .insert_auth_code(&client_id, &user_id, redirect_uris)
        .await;

    assert!(result.is_ok(), "insert_auth_code should succeed: {:?}", result);
    let code = result.unwrap();
    assert_eq!(code.len(), 30);
    assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
}


#[tokio::test]
#[ignore = "NEKOXDB_* を設定し、Postgres と oidc_clients テーブル が必要"]
async fn integration_register_client_with_real_db() {
    let dsn = match test_dsn() {
        Some(s) => s,
        None => {
            eprintln!("skip: NEKOXDB_* not set");
            return;
        }
    };
    let pool = sqlx::PgPool::connect(&dsn).await.expect("DB connect");
    let store = PgClientStore(pool);
    let client_name = format!("{}_{}", "test_client", uuid::Uuid::new_v4().to_string());
    let redirect_uris = vec!["http://localhost:18080/callback"];
    let grant_types = vec!["authorization_code"];
    let result = store.register_client(client_name.as_str(), redirect_uris, grant_types).await;
    assert!(result.is_ok(), "register_client should succeed: {:?}", result);
    let secret = result.unwrap();
    println!("Client Name: {}, secret: {}", client_name, secret);
    assert!(secret.len() > 0);
}