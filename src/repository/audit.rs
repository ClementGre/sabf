use uuid::Uuid;

pub async fn log(
    executor: impl sqlx::PgExecutor<'_>,
    actor_user_id: Option<Uuid>,
    action: &str,
    app_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
) -> sqlx::Result<()> {
    let id = uuid::Uuid::now_v7();
    sqlx::query!(
        r#"
        INSERT INTO audit_log (id, actor_user_id, action, app_id, target_user_id)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        id,
        actor_user_id,
        action,
        app_id,
        target_user_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}
