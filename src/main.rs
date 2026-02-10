use sqlx::PgPool;
use uuid::Uuid;

mod auth;

#[tokio::main]
async fn main() {
    let database_host = std::env::var("NEKOXDB_HOST").expect("DATABASE_URL must be set");
    //let database_host = "192.168.0.159";
    let database_port = std::env::var("NEKOXDB_PORT").expect("DATABASE_PORT must be set");
    let database_user = std::env::var("NEKOXDB_USER").expect("DATABASE_USER must be set");
    let database_password = std::env::var("NEKOXDB_PASSWD").expect("DATABASE_PASSWORD must be set");
    let dsn = format!("postgres://{}:{}@{}:{}/neko_ident?sslmode=disable", database_user, database_password, database_host, database_port);
    println!("DSN: {}", dsn);
    let pool = PgPool::connect(&dsn).await.unwrap();
    let client_id = "60cdabfb-7752-4797-8646-095f2b47e04b";
    let user_id = Uuid::new_v4();
    let redirect_uris = "nekoxsrvx1.local:18080/callback";
    let code = auth::codes::issue_code(&pool, &client_id, &user_id, &redirect_uris).await.unwrap();
    println!("Code: {}", code);
}
