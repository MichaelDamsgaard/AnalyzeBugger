//! MCP HTTP API Server
//!
//! Exposes AnalyzeBugger's state and functionality via HTTP for the MCP server.
//! Runs on localhost:19550 to allow Claude Code integration.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

/// Port for the MCP HTTP API
pub const MCP_API_PORT: u16 = 19550;

/// Pane data for Matrix/Minority Report style UI
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PaneData {
    pub pane_id: String,
    pub data: serde_json::Value,
    pub updated_at: u64,
}

/// Address highlight for visual emphasis
#[derive(Clone, Serialize, Deserialize)]
pub struct Highlight {
    pub addresses: Vec<String>,
    pub color: String,
}

/// Bookmark for quick navigation
#[derive(Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub address: String,
    pub name: String,
    pub notes: String,
}

/// Shared application state for the MCP API
#[derive(Clone)]
pub struct McpApiState {
    /// Current analysis result (JSON)
    pub analysis_result: Arc<RwLock<Option<serde_json::Value>>>,
    /// Current file path
    pub current_file: Arc<RwLock<Option<String>>>,
    /// Current address/view
    pub current_address: Arc<RwLock<Option<String>>>,
    /// Labels set by user/Claude
    pub labels: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// Comments set by user/Claude
    pub comments: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// Project root path (for source code access)
    pub project_root: String,
    /// Pane data for Matrix/Minority Report style UI
    pub panes: Arc<RwLock<std::collections::HashMap<String, PaneData>>>,
    /// Address highlights
    pub highlights: Arc<RwLock<Vec<Highlight>>>,
    /// Bookmarks
    pub bookmarks: Arc<RwLock<Vec<Bookmark>>>,
}

impl McpApiState {
    pub fn new(project_root: String) -> Self {
        Self {
            analysis_result: Arc::new(RwLock::new(None)),
            current_file: Arc::new(RwLock::new(None)),
            current_address: Arc::new(RwLock::new(None)),
            labels: Arc::new(RwLock::new(std::collections::HashMap::new())),
            comments: Arc::new(RwLock::new(std::collections::HashMap::new())),
            project_root,
            panes: Arc::new(RwLock::new(std::collections::HashMap::new())),
            highlights: Arc::new(RwLock::new(Vec::new())),
            bookmarks: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

// ============================================================================
// API Response Types
// ============================================================================

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(data: T) -> Self {
        Self { success: true, data: Some(data), error: None }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self { success: false, data: None, error: Some(msg.into()) }
    }
}

#[derive(Serialize)]
struct AppState {
    current_file: Option<String>,
    current_address: Option<String>,
    has_analysis: bool,
    label_count: usize,
    comment_count: usize,
    api_version: &'static str,
}

#[derive(Deserialize)]
struct NavigateRequest {
    address: String,
}

#[derive(Deserialize)]
struct LabelRequest {
    address: String,
    label: String,
}

#[derive(Deserialize)]
struct CommentRequest {
    address: String,
    comment: String,
}

#[derive(Deserialize)]
struct SourceReadRequest {
    path: String,
}

#[derive(Deserialize)]
struct SourceWriteRequest {
    path: String,
    content: String,
}

#[derive(Deserialize)]
struct ShowPaneRequest {
    pane_id: String,
    data: serde_json::Value,
}

#[derive(Deserialize)]
struct HighlightRequest {
    addresses: Vec<String>,
    #[serde(default = "default_highlight_color")]
    color: String,
}

fn default_highlight_color() -> String {
    "yellow".to_string()
}

#[derive(Deserialize)]
struct BookmarkRequest {
    address: String,
    name: String,
    #[serde(default)]
    notes: String,
}

// ============================================================================
// API Handlers
// ============================================================================

/// GET /health - Health check
async fn health() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse::ok("AnalyzeBugger MCP API is running"))
}

/// GET /state - Get current application state
async fn get_state(State(state): State<McpApiState>) -> Json<ApiResponse<AppState>> {
    let current_file = state.current_file.read().await.clone();
    let current_address = state.current_address.read().await.clone();
    let has_analysis = state.analysis_result.read().await.is_some();
    let label_count = state.labels.read().await.len();
    let comment_count = state.comments.read().await.len();

    Json(ApiResponse::ok(AppState {
        current_file,
        current_address,
        has_analysis,
        label_count,
        comment_count,
        api_version: "1.0.0",
    }))
}

/// GET /analysis - Get current analysis result
async fn get_analysis(State(state): State<McpApiState>) -> Json<ApiResponse<serde_json::Value>> {
    let analysis = state.analysis_result.read().await;
    match analysis.as_ref() {
        Some(result) => Json(ApiResponse::ok(result.clone())),
        None => Json(ApiResponse::err("No analysis loaded")),
    }
}

/// POST /navigate - Navigate to an address
async fn navigate(
    State(state): State<McpApiState>,
    Json(req): Json<NavigateRequest>,
) -> Json<ApiResponse<String>> {
    let mut addr = state.current_address.write().await;
    *addr = Some(req.address.clone());
    Json(ApiResponse::ok(format!("Navigated to {}", req.address)))
}

/// POST /label - Set a label at an address
async fn set_label(
    State(state): State<McpApiState>,
    Json(req): Json<LabelRequest>,
) -> Json<ApiResponse<String>> {
    let mut labels = state.labels.write().await;
    labels.insert(req.address.clone(), req.label.clone());
    Json(ApiResponse::ok(format!("Label '{}' set at {}", req.label, req.address)))
}

/// POST /comment - Set a comment at an address
async fn set_comment(
    State(state): State<McpApiState>,
    Json(req): Json<CommentRequest>,
) -> Json<ApiResponse<String>> {
    let mut comments = state.comments.write().await;
    comments.insert(req.address.clone(), req.comment.clone());
    Json(ApiResponse::ok(format!("Comment set at {}", req.address)))
}

/// GET /labels - Get all labels
async fn get_labels(State(state): State<McpApiState>) -> Json<ApiResponse<std::collections::HashMap<String, String>>> {
    let labels = state.labels.read().await.clone();
    Json(ApiResponse::ok(labels))
}

/// GET /comments - Get all comments
async fn get_comments(State(state): State<McpApiState>) -> Json<ApiResponse<std::collections::HashMap<String, String>>> {
    let comments = state.comments.read().await.clone();
    Json(ApiResponse::ok(comments))
}

/// POST /source/read - Read a source file from the project
async fn read_source(
    State(state): State<McpApiState>,
    Json(req): Json<SourceReadRequest>,
) -> Json<ApiResponse<String>> {
    // Security: only allow reading from project directory
    let full_path = std::path::Path::new(&state.project_root).join(&req.path);

    // Verify path is within project root
    match full_path.canonicalize() {
        Ok(canonical) => {
            let root_canonical = match std::path::Path::new(&state.project_root).canonicalize() {
                Ok(r) => r,
                Err(e) => return Json(ApiResponse::err(format!("Invalid project root: {}", e))),
            };

            if !canonical.starts_with(&root_canonical) {
                return Json(ApiResponse::err("Access denied: path outside project"));
            }

            match std::fs::read_to_string(&canonical) {
                Ok(content) => Json(ApiResponse::ok(content)),
                Err(e) => Json(ApiResponse::err(format!("Failed to read file: {}", e))),
            }
        }
        Err(e) => Json(ApiResponse::err(format!("Invalid path: {}", e))),
    }
}

/// POST /source/write - Write to a source file in the project
async fn write_source(
    State(state): State<McpApiState>,
    Json(req): Json<SourceWriteRequest>,
) -> Json<ApiResponse<String>> {
    // Security: only allow writing to project directory
    let full_path = std::path::Path::new(&state.project_root).join(&req.path);

    // For new files, check parent directory
    let check_path = if full_path.exists() {
        full_path.clone()
    } else {
        match full_path.parent() {
            Some(p) if p.exists() => p.to_path_buf(),
            _ => return Json(ApiResponse::err("Parent directory does not exist")),
        }
    };

    match check_path.canonicalize() {
        Ok(canonical) => {
            let root_canonical = match std::path::Path::new(&state.project_root).canonicalize() {
                Ok(r) => r,
                Err(e) => return Json(ApiResponse::err(format!("Invalid project root: {}", e))),
            };

            // For existing files, check the file itself; for new files, check parent
            let check_against = if full_path.exists() {
                canonical
            } else {
                canonical
            };

            if !check_against.starts_with(&root_canonical) {
                return Json(ApiResponse::err("Access denied: path outside project"));
            }

            // Create parent directories if needed
            if let Some(parent) = full_path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return Json(ApiResponse::err(format!("Failed to create directories: {}", e)));
                }
            }

            match std::fs::write(&full_path, &req.content) {
                Ok(_) => Json(ApiResponse::ok(format!("Written {} bytes to {}", req.content.len(), req.path))),
                Err(e) => Json(ApiResponse::err(format!("Failed to write file: {}", e))),
            }
        }
        Err(e) => Json(ApiResponse::err(format!("Invalid path: {}", e))),
    }
}

/// GET /source/list/:path - List files in a directory
async fn list_source(
    State(state): State<McpApiState>,
    Path(path): Path<String>,
) -> Json<ApiResponse<Vec<String>>> {
    let full_path = std::path::Path::new(&state.project_root).join(&path);

    match full_path.canonicalize() {
        Ok(canonical) => {
            let root_canonical = match std::path::Path::new(&state.project_root).canonicalize() {
                Ok(r) => r,
                Err(e) => return Json(ApiResponse::err(format!("Invalid project root: {}", e))),
            };

            if !canonical.starts_with(&root_canonical) {
                return Json(ApiResponse::err("Access denied: path outside project"));
            }

            match std::fs::read_dir(&canonical) {
                Ok(entries) => {
                    let files: Vec<String> = entries
                        .filter_map(|e| e.ok())
                        .map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            if e.path().is_dir() {
                                format!("{}/", name)
                            } else {
                                name
                            }
                        })
                        .collect();
                    Json(ApiResponse::ok(files))
                }
                Err(e) => Json(ApiResponse::err(format!("Failed to list directory: {}", e))),
            }
        }
        Err(e) => Json(ApiResponse::err(format!("Invalid path: {}", e))),
    }
}

// ============================================================================
// Matrix/Minority Report Style Pane Control
// ============================================================================

/// POST /pane/show - Display data in a UI pane
async fn show_pane(
    State(state): State<McpApiState>,
    Json(req): Json<ShowPaneRequest>,
) -> Json<ApiResponse<String>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let pane_data = PaneData {
        pane_id: req.pane_id.clone(),
        data: req.data,
        updated_at: timestamp,
    };

    let mut panes = state.panes.write().await;
    panes.insert(req.pane_id.clone(), pane_data);

    Json(ApiResponse::ok(format!("Pane '{}' updated", req.pane_id)))
}

/// GET /pane/:pane_id - Get data from a specific pane
async fn get_pane(
    State(state): State<McpApiState>,
    Path(pane_id): Path<String>,
) -> Json<ApiResponse<PaneData>> {
    let panes = state.panes.read().await;
    match panes.get(&pane_id) {
        Some(pane) => Json(ApiResponse::ok(pane.clone())),
        None => Json(ApiResponse::err(format!("Pane '{}' not found", pane_id))),
    }
}

/// GET /panes - Get all pane data
async fn get_all_panes(
    State(state): State<McpApiState>,
) -> Json<ApiResponse<std::collections::HashMap<String, PaneData>>> {
    let panes = state.panes.read().await.clone();
    Json(ApiResponse::ok(panes))
}

/// POST /highlight - Highlight addresses in the UI
async fn set_highlights(
    State(state): State<McpApiState>,
    Json(req): Json<HighlightRequest>,
) -> Json<ApiResponse<String>> {
    let highlight = Highlight {
        addresses: req.addresses.clone(),
        color: req.color.clone(),
    };

    let mut highlights = state.highlights.write().await;
    highlights.push(highlight);

    Json(ApiResponse::ok(format!(
        "Highlighted {} addresses in {}",
        req.addresses.len(),
        req.color
    )))
}

/// GET /highlights - Get all highlights
async fn get_highlights(
    State(state): State<McpApiState>,
) -> Json<ApiResponse<Vec<Highlight>>> {
    let highlights = state.highlights.read().await.clone();
    Json(ApiResponse::ok(highlights))
}

/// DELETE /highlights - Clear all highlights
async fn clear_highlights(
    State(state): State<McpApiState>,
) -> Json<ApiResponse<String>> {
    let mut highlights = state.highlights.write().await;
    let count = highlights.len();
    highlights.clear();
    Json(ApiResponse::ok(format!("Cleared {} highlights", count)))
}

/// POST /bookmark - Create a bookmark
async fn create_bookmark(
    State(state): State<McpApiState>,
    Json(req): Json<BookmarkRequest>,
) -> Json<ApiResponse<String>> {
    let bookmark = Bookmark {
        address: req.address.clone(),
        name: req.name.clone(),
        notes: req.notes,
    };

    let mut bookmarks = state.bookmarks.write().await;
    bookmarks.push(bookmark);

    Json(ApiResponse::ok(format!(
        "Bookmark '{}' created at {}",
        req.name,
        req.address
    )))
}

/// GET /bookmarks - Get all bookmarks
async fn get_bookmarks(
    State(state): State<McpApiState>,
) -> Json<ApiResponse<Vec<Bookmark>>> {
    let bookmarks = state.bookmarks.read().await.clone();
    Json(ApiResponse::ok(bookmarks))
}

/// DELETE /bookmark/:address - Delete a bookmark by address
async fn delete_bookmark(
    State(state): State<McpApiState>,
    Path(address): Path<String>,
) -> Json<ApiResponse<String>> {
    let mut bookmarks = state.bookmarks.write().await;
    let initial_len = bookmarks.len();
    bookmarks.retain(|b| b.address != address);
    let removed = initial_len - bookmarks.len();

    if removed > 0 {
        Json(ApiResponse::ok(format!("Removed bookmark at {}", address)))
    } else {
        Json(ApiResponse::err(format!("No bookmark found at {}", address)))
    }
}

// ============================================================================
// Server Setup
// ============================================================================

/// Create the MCP API router
pub fn create_router(state: McpApiState) -> Router {
    use axum::routing::delete;

    Router::new()
        // Health and state
        .route("/health", get(health))
        .route("/state", get(get_state))
        .route("/analysis", get(get_analysis))
        // Navigation and annotations
        .route("/navigate", post(navigate))
        .route("/label", post(set_label))
        .route("/comment", post(set_comment))
        .route("/labels", get(get_labels))
        .route("/comments", get(get_comments))
        // Source code access (self-modification)
        .route("/source/read", post(read_source))
        .route("/source/write", post(write_source))
        .route("/source/list/*path", get(list_source))
        // Matrix/Minority Report style pane control
        .route("/pane/show", post(show_pane))
        .route("/pane/{pane_id}", get(get_pane))
        .route("/panes", get(get_all_panes))
        // Address highlighting
        .route("/highlight", post(set_highlights))
        .route("/highlights", get(get_highlights))
        .route("/highlights", delete(clear_highlights))
        // Bookmarks
        .route("/bookmark", post(create_bookmark))
        .route("/bookmarks", get(get_bookmarks))
        .route("/bookmark/{address}", delete(delete_bookmark))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Start the MCP API server
pub async fn start_server(state: McpApiState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", MCP_API_PORT)).await?;

    eprintln!("[MCP API] Server starting on http://127.0.0.1:{}", MCP_API_PORT);

    axum::serve(listener, app).await?;

    Ok(())
}
