    HttpResponse::NoContent().finish()
}
// Add this new handler for completed todos
#[get("/todos/completed")]
async fn completed_todos_handler(
    opts: web::Query<QueryOptions>,
    data: web::Data<AppState>,
) -> impl Responder {
    let todos = data.todo_db.lock().unwrap();
    let limit = opts.limit.unwrap_or(10);
    let offset = (opts.page.unwrap_or(1) - 1) * limit;

    // Filter completed todos
    let completed_todos: Vec<Todo> = todos
        .clone()
        .into_iter()
        .filter(|todo| todo.completed.unwrap_or(false))
        .skip(offset)
        .take(limit)
        .collect();

    let json_response = TodoListResponse {
        status: "success".to_string(),
        results: completed_todos.len(),
        todos: completed_todos,
    };
    HttpResponse::Ok().json(json_response)
