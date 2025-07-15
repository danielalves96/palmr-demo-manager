use bollard::{Docker, container::LogsOptions};
use futures_util::stream::StreamExt;
use bollard::container::LogOutput;
use tracing::{info, error};
use crate::AppState;

pub fn spawn_monitor(container_name: String, instance_id: String, use_traefik: bool, state: AppState, max_attempts: usize, base_domain: String, domain_prefix: String) {
    let state_clone = state.clone();
    tokio::spawn(async move {
        let docker_bg = match Docker::connect_with_local_defaults() {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to connect to Docker: {}", e);
                return;
            }
        };
        let mut attempts = 0;
        let mut api_ready = false;
        let mut access_url: Option<String> = None;

        while attempts < max_attempts && !api_ready {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            attempts += 1;

            match docker_bg.inspect_container(&container_name, None).await {
                Ok(_) => {
                }
                Err(_) => {
                    error!("Container {} no longer exists, stopping monitoring", container_name);
                    break;
                }
            }

            let mut log_stream = docker_bg.logs(&container_name, Some(LogsOptions::<String> {
                follow: false,
                stdout: true,
                stderr: true,
                tail: "20".to_string(),
                ..Default::default()
            }));

            let mut log_string = String::new();
            while let Some(log_output_result) = log_stream.next().await {
                match log_output_result {
                    Ok(log_output) => {
                        match log_output {
                            LogOutput::StdOut { message } => log_string.push_str(&String::from_utf8_lossy(&message)),
                            LogOutput::StdErr { message } => log_string.push_str(&String::from_utf8_lossy(&message)),
                            _ => {},
                        }
                    }
                    Err(e) => {
                        error!("Error reading log stream for {}: {}", container_name, e);
                        break;
                    }
                }
            }
            if log_string.contains("API is ready! Starting frontend...") {
                api_ready = true;
                info!("API ready message found for container {}. Waiting 10 seconds for frontend.", container_name);
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                
                access_url = Some(if use_traefik {
                    format!("https://{}-{}.{}", instance_id, domain_prefix, base_domain)
                } else {
                    "http://localhost:5487".to_string()
                });
                info!("Container {} fully ready. Access URL: {}", container_name, access_url.as_ref().unwrap());
            }
        }
        let mut state_guard = state_clone.states.lock().unwrap();
        if let Some(url) = access_url {
            state_guard.insert(instance_id, Some(url));
        } else {
            state_guard.insert(instance_id, Some("timeout".to_string()));
        }
    });
}

pub fn spawn_cleanup(instance_id: String, state: AppState, delay_sec: u64) {
    let state_clone = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(delay_sec)).await;
        
        let docker = match Docker::connect_with_local_defaults() {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to connect to Docker for auto cleanup of {}: {}", instance_id, e);
                return;
            }
        };
        
        let container_name = format!("{}-palmr-demo", &instance_id);
        info!("Auto cleaning up container: {}", container_name);
        
        if let Err(_) = docker.inspect_container(&container_name, None).await {
            info!("Container {} no longer exists, skipping cleanup", container_name);
            state_clone.states.lock().unwrap().remove(&instance_id);
            return;
        }
        
        if let Err(e) = docker.stop_container(&container_name, Some(bollard::container::StopContainerOptions {
            t: 10,
        })).await {
            error!("Failed to stop container {}: {}", container_name, e);
        }
        
        if let Err(e) = docker.remove_container(&container_name, None).await {
            error!("Failed to remove container {}: {}", container_name, e);
        }
        
        let volume_name = format!("palmr_data_{}", &instance_id);
        if let Err(e) = docker.remove_volume(&volume_name, None).await {
            error!("Failed to remove volume {}: {}", volume_name, e);
        }
        
        state_clone.states.lock().unwrap().remove(&instance_id);
        info!("Auto cleanup completed for {}", instance_id);
    });
}