use serde::{Deserialize, Serialize};
use bollard::{Docker, container::{NetworkingConfig, ListContainersOptions}};
use uuid::Uuid;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
use axum::{routing::{post, get}, Json, Router, extract::{State, Path}};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::Utc;
use axum::response::{IntoResponse, Response};
use tower_http::cors::CorsLayer;
use std::net::IpAddr;
use axum::extract::ConnectInfo;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod utils;

use utils::{spawn_monitor, spawn_cleanup};

#[derive(Debug)]
enum AppError {
    Internal(anyhow::Error),
    RateLimitExceeded,
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}

impl From<bollard::errors::Error> for AppError {
    fn from(err: bollard::errors::Error) -> Self {
        AppError::Internal(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Internal(err) => {
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
            AppError::RateLimitExceeded => {
                (
                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Maximum 3 requests per minute per IP."
                ).into_response()
            }
        }
    }
}

#[derive(Clone)]
struct AppStateStruct {
    states: Arc<Mutex<HashMap<String, Option<String>>>>,
    cleanup_age_sec: i64,
}
type AppState = AppStateStruct;

// Simple rate limiter: 3 requests per minute per IP
lazy_static::lazy_static! {
    static ref RATE_LIMITER: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>> = {
        Arc::new(Mutex::new(HashMap::new()))
    };
}

fn check_rate_limit(ip: IpAddr) -> Result<(), AppError> {
    let mut rate_limiter = RATE_LIMITER.lock().unwrap();
    let now = Instant::now();
    let window = Duration::from_secs(60); // 1 minute window
    
    // Clean old entries
    if let Some(timestamps) = rate_limiter.get_mut(&ip) {
        timestamps.retain(|&timestamp| now.duration_since(timestamp) < window);
        
        if timestamps.len() >= 3 {
            return Err(AppError::RateLimitExceeded);
        }
        
        timestamps.push(now);
    } else {
        rate_limiter.insert(ip, vec![now]);
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cleanup_age_sec: i64 = std::env::var("CLEANUP_AGE_SEC").ok().and_then(|s| s.parse().ok()).unwrap_or(1800);

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    let states = Arc::new(Mutex::new(HashMap::new()));
    let app_state = AppStateStruct { states, cleanup_age_sec };

    let docker = Docker::connect_with_local_defaults()?;
    
    let use_traefik = std::env::var("USE_TRAEFIK").unwrap_or("false".to_string()).parse::<bool>().unwrap_or(false);
    if use_traefik {
        match docker.inspect_network::<&str>("dokploy-network", None).await {
            Ok(_) => info!("Network dokploy-network found"),
            Err(_) => {
                error!("Network dokploy-network not found! Please create it with: docker network create dokploy-network");
                return Err(anyhow::anyhow!("Required network dokploy-network not found"));
            }
        }
    }
    
    let mut filters = HashMap::new();
    filters.insert("name".to_string(), vec!["-palmr-demo".to_string()]);
    let options = Some(ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    });
    if let Ok(containers) = docker.list_containers(options).await {
        let now = Utc::now().timestamp();
        for container in containers {
            if let Some(names) = &container.names {
                let is_manager = names.iter().any(|name| name.contains("palmr-demo-manager"));
                if is_manager {
                    continue;
                }
            }
            
            if let Some(created) = container.created {
                let age_sec = (now - created) as u64;
                let empty_vec = vec![];
                let names = container.names.as_ref().unwrap_or(&empty_vec);
                let mut instance_id_opt = None;
                for name in names {
                    if name.ends_with("-palmr-demo") {
                        instance_id_opt = Some(name.trim_start_matches("/").trim_end_matches("-palmr-demo").to_string());
                        break;
                    }
                }
                if let Some(instance_id) = instance_id_opt {
                    if age_sec >= cleanup_age_sec as u64 {
                        info!("Removing old container on startup: {}", instance_id);
                        if let Some(id) = container.id {
                            docker.stop_container(&id, None).await.ok();
                            docker.remove_container(&id, None).await.ok();
                        }
                        let volume_name = format!("palmr_data_{}", instance_id);
                        docker.remove_volume(&volume_name, None).await.ok();
                    } else {
        let remaining_sec = cleanup_age_sec as u64 - age_sec;
        let remaining_attempts = (cleanup_age_sec / 10) as usize - (age_sec as usize / 10);
        let container_name = format!("{}-palmr-demo", instance_id);
            let use_traefik = std::env::var("USE_TRAEFIK").unwrap_or("false".to_string()).parse::<bool>().unwrap_or(false);
    let base_domain = std::env::var("BASE_DOMAIN").unwrap_or("kyantech.com.br".to_string());
    let domain_prefix = std::env::var("DOMAIN_PREFIX").unwrap_or("palmr".to_string());
    spawn_monitor(container_name, instance_id.clone(), use_traefik, app_state.clone(), remaining_attempts, base_domain, domain_prefix);
        spawn_cleanup(instance_id.clone(), app_state.clone(), remaining_sec);
        app_state.states.lock().unwrap().insert(instance_id, None);
    }
                }
            }
        }
    }

    // Configure CORS
    let cors = CorsLayer::permissive();

    let app = Router::new()
        .route("/create-demo", post(create_demo))
        .route("/status/:id", get(get_status))
        .route("/cleanup", post(cleanup))
        .route("/cleanup-all", post(cleanup_all))
        .layer(cors)
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)) // 1MB limit
        .with_state(app_state);

    let addr = "0.0.0.0:3585".parse::<std::net::SocketAddr>()?;
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    Ok(axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?)
}

#[derive(Deserialize)]
struct CreateDemoPayload {
    palmr_demo_instance_id: String,
}

#[derive(Serialize)]
struct CreateDemoResponse {
    message: String,
    url: Option<String>,
}

#[axum::debug_handler]
async fn create_demo(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>, 
    Json(payload): Json<CreateDemoPayload>
) -> Result<Json<CreateDemoResponse>, AppError> {
    // Apply rate limiting
    let ip = addr.ip();
    check_rate_limit(ip)?;
    info!("Rate limit check passed for IP: {}. Creating demo for ID: {}", ip, payload.palmr_demo_instance_id);

    let docker = Docker::connect_with_local_defaults()?;
    let encryption_key = Uuid::new_v4().to_string().replace("-", "");
    let instance_id = payload.palmr_demo_instance_id;
    let container_name = format!("{}-palmr-demo", instance_id);
    let volume_name = format!("palmr_data_{}", instance_id);
    
    if let Ok(_) = docker.inspect_container(&container_name, None).await {
        return Err(AppError::Internal(anyhow::anyhow!("Container {} already exists", container_name)));
    }
    
    {
        let state_guard = state.states.lock().unwrap();
        if state_guard.contains_key(&instance_id) {
            return Err(AppError::Internal(anyhow::anyhow!("Demo instance {} is already being processed", instance_id)));
        }
    }
    let use_traefik = std::env::var("USE_TRAEFIK").ok().and_then(|s| s.parse::<bool>().ok()).unwrap_or(false);
    let base_domain = std::env::var("BASE_DOMAIN").unwrap_or("kyantech.com.br".to_string());
    let domain_prefix = std::env::var("DOMAIN_PREFIX").unwrap_or("palmr".to_string());
    
    let container_port = "5487".to_string();

    let mut network_config = std::collections::HashMap::new();
    let mut labels = None;

    if use_traefik {
        network_config.insert(
            "dokploy-network".to_string(),
            bollard::models::EndpointSettings {
                ipam_config: None,
                links: None,
                aliases: None,
                network_id: Some("dokploy-network".to_string()),
                endpoint_id: None,
                gateway: None,
                ip_address: None,
                mac_address: None,
                driver_opts: None,
                dns_names: None,
                global_ipv6_address: None,
                global_ipv6_prefix_len: None,
                ipv6_gateway: None,
                ip_prefix_len: None,
            }
        );

        let dynamic_host = format!("{}-{}.{}", instance_id, domain_prefix, base_domain);
        let router_web = format!("palmr-demo-{}-web", instance_id);
        let router_websecure = format!("palmr-demo-{}-websecure", instance_id);
        let service_name = format!("palmr-demo-{}-service", instance_id);
        
        labels = Some(std::collections::HashMap::from([
            ("traefik.enable".to_string(), "true".to_string()),
            ("traefik.docker.network".to_string(), "dokploy-network".to_string()),
            (format!("traefik.http.routers.{}.rule", router_web), format!("Host(`{}`)", dynamic_host)),
            (format!("traefik.http.routers.{}.entrypoints", router_web), "web".to_string()),
            (format!("traefik.http.routers.{}.service", router_web), service_name.clone()),
            (format!("traefik.http.routers.{}.middlewares", router_web), "redirect-to-https@file".to_string()),
            (format!("traefik.http.routers.{}.rule", router_websecure), format!("Host(`{}`)", dynamic_host)),
            (format!("traefik.http.routers.{}.entrypoints", router_websecure), "websecure".to_string()),
            (format!("traefik.http.routers.{}.service", router_websecure), service_name.clone()),
            (format!("traefik.http.routers.{}.tls.certresolver", router_websecure), "letsencrypt".to_string()),
            (format!("traefik.http.services.{}.loadbalancer.server.port", service_name), container_port.clone()),
        ]));
    }

    let config = bollard::container::Config {
        image: Some("kyantech/palmr:latest".to_string()),
        env: Some(vec![
            "ENABLE_S3=false".to_string(),
            "DEMO_MODE=true".to_string(),
            format!("ENCRYPTION_KEY={}", encryption_key),
            "PALMR_UID=1000".to_string(),
            "PALMR_GID=1000".to_string(),
            "SECURE_SITE=true".to_string(),
        ]),
        labels,
        host_config: Some(bollard::models::HostConfig {
            binds: Some(vec![format!("{}:/app/server", volume_name)]),
            ..Default::default()
        }),
        networking_config: Some(NetworkingConfig {
            endpoints_config: network_config,
        }),
        ..Default::default()
    };

    let container = docker.create_container(Some(bollard::container::CreateContainerOptions {
        name: container_name.clone(),
        ..Default::default()
    }), config).await.map_err(|e| AppError::Internal(e.into()))?;
info!("Container {} created with ID: {}", container_name, container.id);
docker.start_container::<String>(&container_name, None).await.map_err(|e| AppError::Internal(e.into()))?;
info!("Container {} started successfully. Starting background monitoring.", container_name);
{
    let mut state_guard = state.states.lock().unwrap();
    state_guard.insert(instance_id.clone(), None);
}
spawn_monitor(container_name.clone(), instance_id.clone(), use_traefik, state.clone(), (state.cleanup_age_sec / 10) as usize, base_domain, domain_prefix);
spawn_cleanup(instance_id.clone(), state.clone(), state.cleanup_age_sec as u64);
Ok(Json(CreateDemoResponse {
    message: format!("Container {} created and started. Waiting for services to be ready. Check /status/{}", container_name, instance_id),
    url: None,
}))
}

#[derive(Serialize)]
struct CleanupResponse {
    message: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    url: Option<String>,
}

#[axum::debug_handler]
async fn get_status(State(state): State<AppState>, Path(id): Path<String>) -> Json<StatusResponse> {
    info!("Status requested for id: {}", id);
    let state_guard = state.states.lock().unwrap();
    match state_guard.get(&id) {
        Some(Some(url)) if url != "timeout" => Json(StatusResponse { status: "ready".to_string(), url: Some(url.clone()) }),
        Some(Some(_)) => Json(StatusResponse { status: "timeout".to_string(), url: None }),
        _ => Json(StatusResponse { status: "waiting".to_string(), url: None }),
    }
}

async fn cleanup(State(state): State<AppState>) -> Json<CleanupResponse> {
    info!("Received request to cleanup old demo instances.");
    let docker = match Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Failed to connect to Docker for cleanup: {}", e);
            return Json(CleanupResponse { message: "Failed to connect to Docker".to_string() });
        }
    };

    let mut filters = std::collections::HashMap::new();
    filters.insert("name".to_string(), vec!["-palmr-demo".to_string()]);

    let options = Some(bollard::container::ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    });

    let containers = match docker.list_containers(options).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to list containers: {}", e);
            return Json(CleanupResponse { message: "Failed to list containers".to_string() });
        }
    };

    let mut cleaned_up_count = 0;
    let mut errors = Vec::new();
    let now = Utc::now().timestamp();

    for container in containers {
        if let Some(names) = &container.names {
            let is_manager = names.iter().any(|name| name.contains("palmr-demo-manager"));
            if is_manager {
                continue;
            }
        }
        
        if let Some(created_at) = container.created {
            if now - created_at > state.cleanup_age_sec {
                if let Some(container_id) = container.id {
                    info!("Cleaning up old container: {}", container_id);
                    
                    if let Err(e) = docker.stop_container(&container_id, Some(bollard::container::StopContainerOptions {
                        t: 10,
                    })).await {
                        errors.push(format!("Failed to stop container {}: {}", container_id, e));
                        continue;
                    }
                    
                    if let Err(e) = docker.remove_container(&container_id, None).await {
                        errors.push(format!("Failed to remove container {}: {}", container_id, e));
                        continue;
                    }

                    if let Some(names) = container.names {
                        for name in names {
                            if name.ends_with("-palmr-demo") {
                                let instance_id = name.trim_start_matches("/").trim_end_matches("-palmr-demo");
                                let volume_name = format!("palmr_data_{}", instance_id);
                                info!("Removing volume: {}", volume_name);
                                if let Err(e) = docker.remove_volume(&volume_name, None).await {
                                    errors.push(format!("Failed to remove volume {}: {}", volume_name, e));
                                }
                                state.states.lock().unwrap().remove(&instance_id.to_string());
                                break;
                            }
                        }
                    }
                    cleaned_up_count += 1;
                }
            }
        }
    }

    let message = if errors.is_empty() {
        format!("Cleanup complete. Removed {} old demo instances.", cleaned_up_count)
    } else {
        format!("Cleanup completed with {} errors. Removed {} old demo instances. Errors: {}", 
                errors.len(), cleaned_up_count, errors.join("; "))
    };

    Json(CleanupResponse { message })
}

async fn cleanup_all(State(state): State<AppState>) -> Json<CleanupResponse> {
    info!("Received request to cleanup ALL demo instances.");
    let docker = match Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Failed to connect to Docker for cleanup: {}", e);
            return Json(CleanupResponse { message: "Failed to connect to Docker".to_string() });
        }
    };

    let mut filters = std::collections::HashMap::new();
    filters.insert("name".to_string(), vec!["-palmr-demo".to_string()]);

    let options = Some(bollard::container::ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    });

    let containers = match docker.list_containers(options).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to list containers: {}", e);
            return Json(CleanupResponse { message: "Failed to list containers".to_string() });
        }
    };

    let mut cleaned_up_count = 0;
    let mut errors = Vec::new();

    for container in containers {
        if let Some(names) = &container.names {
            let is_manager = names.iter().any(|name| name.contains("palmr-demo-manager"));
            if is_manager {
                continue;
            }
        }
        
        if let Some(container_id) = container.id {
            info!("Cleaning up container: {}", container_id);
            
            if let Err(e) = docker.stop_container(&container_id, Some(bollard::container::StopContainerOptions {
                t: 10,
            })).await {
                errors.push(format!("Failed to stop container {}: {}", container_id, e));
                continue;
            }
            
            if let Err(e) = docker.remove_container(&container_id, None).await {
                errors.push(format!("Failed to remove container {}: {}", container_id, e));
                continue;
            }

            if let Some(names) = container.names {
                for name in names {
                    if name.ends_with("-palmr-demo") {
                        let instance_id = name.trim_start_matches("/").trim_end_matches("-palmr-demo");
                        let volume_name = format!("palmr_data_{}", instance_id);
                        info!("Removing volume: {}", volume_name);
                        if let Err(e) = docker.remove_volume(&volume_name, None).await {
                            errors.push(format!("Failed to remove volume {}: {}", volume_name, e));
                        }
                        state.states.lock().unwrap().remove(&instance_id.to_string());
                        break;
                    }
                }
            }
            cleaned_up_count += 1;
        }
    }

    let message = if errors.is_empty() {
        format!("Cleanup complete. Removed {} demo instances.", cleaned_up_count)
    } else {
        format!("Cleanup completed with {} errors. Removed {} demo instances. Errors: {}", 
                errors.len(), cleaned_up_count, errors.join("; "))
    };

    Json(CleanupResponse { message })
}
