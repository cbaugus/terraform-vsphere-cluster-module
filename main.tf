locals {
  consul_cloud_autodiscovery_string = "provider=vsphere category_name=${var.consul_cloud_autodiscovery_tag_category} tag_name=${var.consul_cloud_autodiscovery_tag_name} host=${var.vsphere_server} user=${var.vsphere_user} password=${var.vsphere_pass} insecure_ssl=true timeout=2m"
  vault_tcp_listeners = [
    {
      "vault_address"                            = var.vault_address
      "vault_port"                               = var.vault_port
      "vault_cluster_address"                    = var.vault_cluster_address
      "vault_tls_cert_file"                      = var.vault_tls_cert_file
      "vault_tls_key_file"                       = var.vault_tls_key_file
      "vault_tls_ca_file"                        = var.vault_tls_ca_file
      "vault_tls_min_version"                    = var.vault_tls_min_version
      "vault_tls_cipher_suites"                  = var.vault_tls_cipher_suites
      "vault_tls_prefer_server_cipher_suites"    = var.vault_tls_prefer_server_cipher_suites
      "vault_tls_require_and_verify_client_cert" = var.vault_tls_require_and_verify_client_cert
      "vault_tls_disable_client_certs"           = var.vault_tls_disable_client_certs
      "vault_tls_disable"                        = var.vault_tls_disable
    }
  ]
  ansible_extra_vars = {
    "ansible_python_interpreter"             = var.ansible_python_interpreter
    "consul_user"                            = var.consul_user
    "consul_manage_user"                     = var.consul_manage_user
    "consul_group"                           = var.consul_group
    "consul_manage_group"                    = var.consul_manage_group
    "consul_group_name"                      = var.consul_group_name
    "consul_domain"                          = var.consul_domain
    "consul_datacenter"                      = var.vsphere_datacenter
    "consul_node_meta"                       = var.consul_node_meta
    "consul_cloud_autodiscovery"             = var.consul_cloud_autodiscovery
    "consul_cloud_autodiscovery_string"      = local.consul_cloud_autodiscovery_string
    "consul_tls_enable"                      = var.consul_tls_enable
    "consul_tls_ca_crt"                      = var.consul_tls_ca_crt
    "consul_tls_server_crt"                  = var.consul_tls_server_crt
    "consul_tls_server_key"                  = var.consul_tls_server_key
    "consul_src_def"                         = var.consul_src_def
    "consul_tls_src_files"                   = var.consul_tls_src_files
    "consul_tls_verify_incoming"             = var.consul_tls_verify_incoming
    "consul_tls_verify_outgoing"             = var.consul_tls_verify_outgoing
    "consul_tls_verify_server_hostname"      = var.consul_tls_verify_server_hostname
    "consul_tls_min_version"                 = var.consul_tls_min_version
    "consul_tls_cipher_suites"               = var.consul_tls_cipher_suites
    "consul_tls_prefer_server_cipher_suites" = var.consul_tls_prefer_server_cipher_suites
    "auto_encrypt"                           = var.auto_encrypt
    "consul_tls_verify_incoming_rpc"         = var.consul_tls_verify_incoming_rpc
    "consul_tls_verify_incoming_https"       = var.consul_tls_verify_incoming_https
    "consul_encrypt_enable"                  = var.consul_encrypt_enable
    "consul_encrypt_verify_incoming"         = var.consul_encrypt_verify_incoming
    "consul_encrypt_verify_outgoing"         = var.consul_encrypt_verify_outgoing
    "consul_disable_keyring_file"            = var.consul_disable_keyring_file
    "consul_raw_key"                         = var.consul_raw_key
    "consul_node_role"                       = var.consul_node_role
    "consul_bootstrap_expect"                = var.consul_bootstrap_expect
    "consul_bootstrap_expect_value"          = var.consul_bootstrap_expect_value
    "consul_connect_enabled"                 = var.consul_connect_enabled
    "consul_syslog_enable"                   = var.consul_syslog_enable
    "consul_install_remotely"                = var.consul_install_remotely
    "consul_install_upgrade"                 = var.consul_install_upgrade
    "consul_ui"                              = var.consul_ui
    "consul_ui_legacy"                       = var.consul_ui_legacy
    "consul_disable_update_check"            = var.consul_disable_update_check
    "consul_enable_script_checks"            = var.consul_enable_script_checks
    "consul_enable_local_script_checks"      = var.consul_enable_local_script_checks
    "consul_raft_protocol"                   = var.consul_raft_protocol
    "consul_version"                         = var.consul_version
    "consul_bin_path"                        = var.consul_bin_path
    "consul_config_path"                     = var.consul_config_path
    "consul_data_path"                       = var.consul_data_path
    "consul_configure_syslogd"               = var.consul_configure_syslogd
    "consul_log_path"                        = var.consul_log_path
    "consul_log_file"                        = var.consul_log_file
    "consul_log_level"                       = var.consul_log_level
    "consul_log_rotate_bytes"                = var.consul_log_rotate_bytes
    "consul_log_rotate_duration"             = var.consul_log_rotate_duration
    "consul_log_rotate_max_files"            = var.consul_log_rotate_max_files
    "consul_syslog_facility"                 = var.consul_syslog_facility
    "syslog_user"                            = var.syslog_user
    "syslog_group"                           = var.syslog_group
    "consul_run_path"                        = var.consul_run_path
    "consul_retry_interval"                  = var.consul_retry_interval
    "consul_retry_interval_wan"              = var.consul_retry_interval_wan
    "consul_retry_join_skip_hosts"           = var.consul_retry_join_skip_hosts
    "consul_retry_max"                       = var.consul_retry_max
    "consul_retry_max_wan"                   = var.consul_retry_max_wan
    "consul_acl_enable"                      = var.consul_acl_enable
    "consul_acl_token"                       = var.consul_acl_token
    "consul_acl_default_policy"              = var.consul_acl_default_policy
    "consul_acl_token_persistence"           = var.consul_acl_token_persistence
    "consul_acl_datacenter"                  = var.consul_acl_datacenter
    "consul_acl_down_policy"                 = var.consul_acl_down_policy
    "consul_acl_agent_token"                 = var.consul_acl_agent_token
    "consul_acl_agent_master_token"          = var.consul_acl_agent_master_token
    "consul_acl_master_token"                = var.consul_acl_master_token
    "consul_acl_master_token_display"        = var.consul_acl_master_token_display
    "consul_acl_replication_token"           = var.consul_acl_replication_token
    "consul_addresses_http"                  = var.consul_addresses_http
    "consul_ports"                           = var.consul_ports
    "consul_dnsmasq_enable"                  = var.consul_dnsmasq_enable
    #"consul_delegate_datacenter_dns"         = ""
    #"consul_dnsmasq_bind_interfaces"         = ""
    #"consul_dnsmasq_consul_address"          = ""
    #"consul_dnsmasq_cache"                   = ""
    "consul_dnsmasq_servers"    = var.consul_dnsmasq_servers
    "consul_dnsmasq_revservers" = var.consul_dnsmasq_revservers
    #"consul_dnsmasq_no_poll"                 = ""
    #"consul_dnsmasq_no_resolv"               = ""
    #"consul_dnsmasq_local_service"           = ""
    #"consul_dnsmasq_listen_addresses"        = ""
    "consul_iptables_enable" = var.consul_iptables_enable
    "consul_recursors"       = var.consul_recursors
    "consul_debug"           = var.consul_debug
    "consul_config_custom"   = var.consul_config_custom

    "docker_daemon_options" = var.docker_daemon_options
    "docker_vault_login"    = var.docker_vault_login

    "vault_docker_secrets" = var.vault_docker_secrets

    "nomad_debug"                                = var.nomad_debug
    "nomad_skip_ensure_all_hosts"                = var.nomad_skip_ensure_all_hosts
    "nomad_allow_purge_config"                   = var.nomad_allow_purge_config
    "nomad_version"                              = var.nomad_version
    "nomad_bin_dir"                              = var.nomad_bin_dir
    "nomad_config_dir"                           = var.nomad_config_dir
    "nomad_data_dir"                             = var.nomad_data_dir
    "nomad_lockfile"                             = var.nomad_lockfile
    "nomad_run_dir"                              = var.nomad_run_dir
    "nomad_manage_user"                          = var.nomad_manage_user
    "nomad_user"                                 = var.nomad_user
    "nomad_user_uid"                             = var.nomad_user_uid
    "nomad_manage_group"                         = var.nomad_manage_group
    "nomad_group"                                = var.nomad_group
    "nomad_group_gid"                            = var.nomad_group_gid
    "nomad_region"                               = var.nomad_region
    "nomad_datacenter"                           = var.nomad_datacenter
    "nomad_log_level"                            = var.nomad_log_level
    "nomad_syslog_enable"                        = var.nomad_syslog_enable
    "nomad_node_role"                            = var.nomad_node_role
    "nomad_leave_on_terminate"                   = var.nomad_leave_on_terminate
    "nomad_leave_on_interrupt"                   = var.nomad_leave_on_interrupt
    "nomad_disable_update_check"                 = var.nomad_disable_update_check
    "nomad_retry_max"                            = var.nomad_retry_max
    "nomad_retry_join"                           = var.nomad_retry_join
    "nomad_retry_interval"                       = var.nomad_retry_interval
    "nomad_rejoin_after_leave"                   = var.nomad_rejoin_after_leave
    "nomad_enabled_schedulers"                   = var.nomad_enabled_schedulers
    "nomad_node_gc_threshold"                    = var.nomad_node_gc_threshold
    "nomad_job_gc_threshold"                     = var.nomad_job_gc_threshold
    "nomad_eval_gc_threshold"                    = var.nomad_eval_gc_threshold
    "nomad_deployment_gc_threshold"              = var.nomad_deployment_gc_threshold
    "nomad_encrypt_enable"                       = var.nomad_encrypt_enable
    "nomad_encrypt"                              = var.nomad_encrypt
    "nomad_raft_protocol"                        = var.nomad_raft_protocol
    "nomad_authoritative_region"                 = var.nomad_authoritative_region
    "nomad_node_class"                           = var.nomad_node_class
    "nomad_no_host_uuid"                         = var.nomad_no_host_uuid
    "nomad_max_kill_timeout"                     = var.nomad_max_kill_timeout
    "nomad_network_interface"                    = var.nomad_network_interface
    "nomad_network_speed"                        = var.nomad_network_speed
    "nomad_cpu_total_compute"                    = var.nomad_cpu_total_compute
    "nomad_gc_interval"                          = var.nomad_gc_interval
    "nomad_gc_disk_usage_threshold"              = var.nomad_gc_disk_usage_threshold
    "nomad_gc_inodes_usage_threshold"            = var.nomad_gc_inodes_usage_threshold
    "nomad_gc_parallel_destroys"                 = var.nomad_gc_parallel_destroys
    "nomad_reserved_cpu"                         = var.nomad_reserved_cpu
    "nomad_reserved_memory"                      = var.nomad_reserved_memory
    "nomad_reserved_disk"                        = var.nomad_reserved_disk
    "nomad_reserved_ports"                       = var.nomad_reserved_ports
    "nomad_host_volumes"                         = var.nomad_host_volumes
    "nomad_options"                              = var.nomad_options
    "nomad_plugins"                              = var.nomad_plugins
    "nomad_meta"                                 = var.nomad_meta
    "nomad_ports_http"                           = var.nomad_ports_http
    "nomad_ports_rpc"                            = var.nomad_ports_rpc
    "nomad_ports_serf"                           = var.nomad_ports_serf
    "nomad_podman_enable"                        = var.nomad_podman_enable
    "nomad_docker_enable"                        = var.nomad_docker_enable
    "nomad_use_consul"                           = var.nomad_use_consul
    "nomad_consul_address"                       = var.nomad_consul_address
    "nomad_consul_servers_service_name"          = var.nomad_consul_servers_service_name
    "nomad_consul_clients_service_name"          = var.nomad_consul_clients_service_name
    "nomad_consul_token"                         = var.nomad_consul_token
    "nomad_acl_enabled"                          = var.nomad_acl_enabled
    "nomad_acl_token_ttl"                        = var.nomad_acl_token_ttl
    "nomad_acl_policy_ttl"                       = var.nomad_acl_policy_ttl
    "nomad_acl_replication_token"                = var.nomad_acl_replication_token
    "nomad_vault_enabled"                        = var.nomad_vault_enabled
    "nomad_vault_allow_unauthenticated"          = var.nomad_vault_allow_unauthenticated
    "nomad_vault_address"                        = var.nomad_vault_address
    "nomad_vault_create_from_role"               = var.nomad_vault_create_from_role
    "nomad_vault_ca_file"                        = var.nomad_vault_ca_file
    "nomad_vault_ca_path"                        = var.nomad_vault_ca_path
    "nomad_vault_cert_file"                      = var.nomad_vault_cert_file
    "nomad_vault_key_file"                       = var.nomad_vault_key_file
    "nomad_vault_tls_server_name"                = var.nomad_vault_tls_server_name
    "nomad_vault_tls_skip_verify"                = var.nomad_vault_tls_skip_verify
    "nomad_vault_namespace"                      = var.nomad_vault_namespace
    "nomad_tls_enable"                           = var.nomad_tls_enable
    "nomad_ca_file"                              = var.nomad_ca_file
    "nomad_cert_file"                            = var.nomad_cert_file
    "nomad_key_file"                             = var.nomad_key_file
    "nomad_rpc_upgrade_mode"                     = var.nomad_rpc_upgrade_mode
    "nomad_verify_server_hostname"               = var.nomad_verify_server_hostname
    "nomad_verify_https_client"                  = var.nomad_verify_https_client
    "nomad_group_name"                           = var.nomad_group_name
    "nomad_telemetry"                            = var.nomad_telemetry
    "nomad_telemetry_prometheus_metrics"         = var.nomad_telemetry_prometheus_metrics
    "nomad_telemetry_publish_allocation_metrics" = var.nomad_telemetry_publish_allocation_metrics
    "nomad_telemetry_publish_node_metrics"       = var.nomad_telemetry_publish_node_metrics
    "nomad_autopilot"                            = var.nomad_autopilot
    "nomad_autopilot_cleanup_dead_servers"       = var.nomad_autopilot_cleanup_dead_servers
    "nomad_autopilot_last_contact_threshold"     = var.nomad_autopilot_last_contact_threshold
    "nomad_autopilot_max_trailing_logs"          = var.nomad_autopilot_max_trailing_logs
    "nomad_autopilot_server_stabilization_time"  = var.nomad_autopilot_server_stabilization_time

    "vault_listener_localhost_enable"                   = var.vault_listener_localhost_enable
    "vault_privileged_install"                          = var.vault_listener_localhost_enable
    "vault_version"                                     = var.vault_version
    "vault_enterprise"                                  = var.vault_enterprise
    "vault_pkg"                                         = var.vault_pkg
    "vault_enterprise_pkg"                              = var.vault_enterprise_pkg
    "vault_zip_url"                                     = var.vault_zip_url
    "vault_checksum_file_url"                           = var.vault_checksum_file_url
    "vault_install_hashi_repo"                          = var.vault_install_hashi_repo
    "vault_install_remotely"                            = var.vault_install_remotely
    "vault_shasums"                                     = var.vault_shasums
    "vault_enterprise_shasums"                          = var.vault_enterprise_shasums
    "vault_bin_path"                                    = var.vault_bin_path
    "vault_config_path"                                 = var.vault_config_path
    "vault_use_config_path"                             = var.vault_use_config_path
    "vault_plugin_path"                                 = var.vault_plugin_path
    "vault_data_path"                                   = var.vault_data_path
    "vault_log_path"                                    = var.vault_log_path
    "vault_run_path"                                    = var.vault_run_path
    "vault_harden_file_perms"                           = var.vault_harden_file_perms
    "vault_manage_user"                                 = var.vault_manage_user
    "vault_user"                                        = var.vault_user
    "vault_group"                                       = var.vault_group
    "vault_groups"                                      = var.vault_groups
    "vault_manage_group"                                = var.vault_manage_group
    "vault_group_name"                                  = var.vault_group_name
    "vault_cluster_name"                                = var.vault_cluster_name
    "vault_datacenter"                                  = var.vault_datacenter
    "vault_ui"                                          = var.vault_ui
    "vault_service_restart"                             = var.vault_service_restart
    "vault_service_reload"                              = var.vault_service_reload
    "vault_start_pause_seconds"                         = var.vault_start_pause_seconds
    "vault_tcp_listeners"                               = local.vault_tcp_listeners
    "vault_backend"                                     = var.vault_backend //only Raft is supported by this module currently, and vars for other storage backends are not added here
    "vault_backend_tls_src_files"                       = var.vault_backend_tls_src_files
    "vault_backend_tls_config_path"                     = var.vault_backend_tls_config_path
    "vault_backend_tls_cert_file"                       = var.vault_backend_tls_cert_file
    "vault_backend_tls_key_file"                        = var.vault_backend_tls_key_file
    "vault_backend_tls_ca_file"                         = var.vault_backend_tls_ca_file
    "vault_raft_leader_tls_servername"                  = var.vault_raft_leader_tls_servername
    "vault_raft_group_name"                             = var.vault_raft_group_name
    "vault_raft_data_path"                              = var.vault_raft_data_path
    "vault_raft_node_id"                                = var.vault_raft_node_id
    "vault_raft_performance_multiplier"                 = var.vault_raft_performance_multiplier
    "vault_raft_trailing_logs"                          = var.vault_raft_trailing_logs
    "vault_raft_snapshot_threshold"                     = var.vault_raft_snapshot_threshold
    "vault_raft_max_entry_size"                         = var.vault_raft_max_entry_size
    "vault_raft_autopilot_reconcile_interval"           = var.vault_raft_autopilot_reconcile_interval
    "vault_raft_cloud_auto_join"                        = var.vault_raft_cloud_auto_join
    "vault_raft_cloud_auto_join_exclusive"              = var.vault_raft_cloud_auto_join_exclusive
    "vault_raft_cloud_auto_join_scheme"                 = var.vault_raft_cloud_auto_join_scheme
    "vault_raft_cloud_auto_join_port"                   = var.vault_raft_cloud_auto_join_port
    "vault_service_registration_consul_enable"          = var.vault_service_registration_consul_enable //only Consul service registration is supported by this module currently, and vars for other service registrations are not added here
    "vault_service_registration_consul_template"        = var.vault_service_registration_consul_template
    "vault_service_registration_consul_address"         = var.vault_service_registration_consul_address
    "vault_service_registration_check_timeout"          = var.vault_service_registration_check_timeout
    "vault_service_registration_disable_registration"   = var.vault_service_registration_disable_registration
    "vault_service_registration_consul_scheme"          = var.vault_service_registration_consul_scheme
    "vault_service_registration_consul_service"         = var.vault_service_registration_consul_service
    "vault_service_registration_consul_service_tags"    = var.vault_service_registration_consul_service_tags
    "vault_service_registration_consul_service_address" = var.vault_service_registration_consul_service_address
    "vault_service_registration_consul_token"           = var.vault_service_registration_consul_token
    "vault_service_registration_consul_tls_config_path" = var.vault_service_registration_consul_tls_config_path
    "vault_service_registration_consul_tls_ca_file"     = var.vault_service_registration_consul_tls_ca_file
    "vault_service_registration_consul_tls_cert_file"   = var.vault_service_registration_consul_tls_cert_file
    "vault_service_registration_consul_tls_key_file"    = var.vault_service_registration_consul_tls_key_file
    "vault_service_registration_consul_tls_min_version" = var.vault_service_registration_consul_tls_min_version
    "vault_service_registration_consul_tls_skip_verify" = var.vault_service_registration_consul_tls_skip_verify
    "vault_log_level"                                   = var.vault_log_level
    "vault_iface"                                       = var.vault_iface
    "vault_address"                                     = var.vault_address
    "vault_port"                                        = var.vault_port
    "vault_max_lease_ttl"                               = var.vault_max_lease_ttl
    "vault_default_lease_ttl"                           = var.vault_default_lease_ttl
    "vault_main_config"                                 = var.vault_main_config
    "vault_main_configuration_template"                 = var.vault_main_configuration_template
    "vault_http_proxy"                                  = var.vault_http_proxy
    "vault_https_proxy"                                 = var.vault_https_proxy
    "vault_no_proxy"                                    = var.vault_no_proxy
    "vault_cluster_address"                             = var.vault_cluster_address
    "vault_cluster_addr"                                = var.vault_cluster_addr
    "vault_api_addr"                                    = var.vault_api_addr
    "vault_disable_api_health_check"                    = var.vault_disable_api_health_check
    "vault_cluster_disable"                             = var.vault_cluster_disable
    "validate_certs_during_api_reachable_check"         = var.validate_certs_during_api_reachable_check
    "vault_proxy_protocol_behavior"                     = var.vault_proxy_protocol_behavior
    "vault_tls_config_path"                             = var.vault_tls_config_path
    "vault_tls_disable"                                 = var.vault_tls_disable
    "vault_tls_gossip"                                  = var.vault_tls_gossip
    "vault_tls_src_files"                               = var.vault_tls_src_files
    "vault_tls_ca_file"                                 = var.vault_tls_ca_file
    "vault_tls_cert_file"                               = var.vault_tls_cert_file
    "vault_tls_key_file"                                = var.vault_tls_key_file
    "vault_tls_min_version"                             = var.vault_tls_min_version
    "vault_tls_cipher_suites"                           = var.vault_tls_cipher_suites
    "vault_tls_prefer_server_cipher_suites"             = var.vault_tls_prefer_server_cipher_suites
    "vault_tls_require_and_verify_client_cert"          = var.vault_tls_require_and_verify_client_cert
    "vault_tls_disable_client_certs"                    = var.vault_tls_disable_client_certs
    "vault_tls_copy_keys"                               = var.vault_tls_copy_keys
    "vault_tls_files_remote_src"                        = var.vault_tls_files_remote_src
    "vault_x_forwarded_for_authorized_addrs"            = var.vault_x_forwarded_for_authorized_addrs
    "vault_bsdinit_template"                            = var.vault_bsdinit_template
    "vault_sysvinit_template"                           = var.vault_sysvinit_template
    "vault_debian_init_template"                        = var.vault_debian_init_template
    "vault_systemd_template"                            = var.vault_systemd_template
    "vault_systemd_service_name"                        = var.vault_systemd_service_name
    "vault_telemetry_enabled"                           = var.vault_telemetry_enabled
    "vault_unauthenticated_metrics_access"              = var.vault_unauthenticated_metrics_access
    //TODO: Add transit auto-unseal when supported

    "vault_agent_role_id"               = var.vault_agent_role_id
    "vault_agent_secret_id"             = var.vault_agent_secret_id
    "vault_agent_version"               = var.vault_agent_version
    "vault_api_address"                 = var.vault_api_address
    "vault_agent_log_level"             = var.vault_agent_log_level
    "vault_agent_templates"             = var.vault_agent_templates
    "vault_consul_role_cluster_type"    = var.vault_consul_role_cluster_type
    "vault_skip_verify"                 = var.vault_skip_verify
    "vault_ca_cert"                     = var.vault_ca_cert
    "vault_ca_path"                     = var.vault_ca_path
    "vault_client_cert"                 = var.vault_client_cert
    "vault_client_key"                  = var.vault_client_key
    "vault_ca_cert_src"                 = var.vault_ca_cert_src
    "vault_client_cert_src"             = var.vault_client_cert_src
    "vault_client_key_src"              = var.vault_client_key_src
    "vault_agent_num_retries"           = var.vault_agent_num_retries
    "vault_agent_exit_on_retry_failure" = var.vault_agent_exit_on_retry_failure

    "known_hosts_user"    = var.known_hosts_user
    "known_hosts_targets" = var.known_hosts_targets

    "nfs_mount_server" = var.nfs_mount_server
    "nfs_mount_options" = var.nfs_mount_options
    "nfs_mount_path" = var.nfs_mount_path

    "growr_env" = merge([for index, disk in var.growr_provisioned_disks : merge({
      // Regular Vars
      "LABEL_${disk.DEVICE_DRIVE}" = disk["LABEL"],
    })]...)
    "s3_env" = merge([for index, disk in var.s3_provisioned_disks : merge({
      // Regular Vars
      "S3_HOST_${index + 1}"                 = disk["S3_HOST_${index + 1}"],
      "S3_MOUNT_${index + 1}"                = disk["S3_MOUNT_${index + 1}"],
      "S3_UID_${index + 1}"                  = disk["S3_UID_${index + 1}"],
      "S3_GID_${index + 1}"                  = disk["S3_GID_${index + 1}"],
      "S3_ACL_${index + 1}"                  = disk["S3_ACL_${index + 1}"],
      "S3_CACHE_${index + 1}"                = disk["S3_CACHE_${index + 1}"]
      "S3_BUCKET_${index + 1}"               = disk["S3_BUCKET_${index + 1}"],
      "S3_NO_CHECK_CERTIFICATE_${index + 1}" = disk["S3_NO_CHECK_CERTIFICATE_${index + 1}"],
      "S3_SSL_VERIFY_HOSTNAME_${index + 1}"  = disk["S3_SSL_VERIFY_HOSTNAME_${index + 1}"],
      "S3_EXTRA_OPTS_${index + 1}"           = disk["S3_EXTRA_OPTS_${index + 1}"]
      // Secret Vars
      "S3_ACCESS_KEY_${index + 1}" = disk["S3_ACCESS_KEY_${index + 1}"],
      "S3_SECRET_KEY_${index + 1}" = disk["S3_SECRET_KEY_${index + 1}"]
    })]...)
  }
}

module "virtual_machines" {
  source  = "app.terraform.io/baugus-lab/vm-module/vsphere"
  version = "2.0.1"
  count   = tonumber(var.num_instances)
  network = {
    (data.vsphere_network.network.name) = var.ip_address
    ### "Network02" = ["10.13.113.2", "10.13.113.3"] # Second Network will use the static
  }
  network_type = data.vsphere_virtual_machine.template.network_interface_types[0]
  ### Disks section
  disk_label     = ["${var.name_prefix}-disk0"]          ### disk0
  disk_size_gb   = [var.disk_size[var.disk_size_type]]   ### disk0
  disk_datastore = data.vsphere_datastore.datastore.name ### disk0
  scsi_type      = "lsilogic"
  data_disk = { for index, disk in var.provisioned_disks : disk.label => {
    "size_gb"                   = "${var.disk_size[disk.disk_size]}"
    "thin_provisioned"          = "${disk.thin_provisioned}"
    "eagerly_scrub"             = "${disk.eagerly_scrub}"
    "datastore_id"              = "${data.vsphere_datastore.datastore.id}"
    "data_disk_scsi_controller" = "${disk.data_disk_scsi_controller}"
  }
  }
  vmname                      = "${var.name_prefix}-${count.index}"
  vmtemp                      = data.vsphere_virtual_machine.template.name
  tag_ids                     = var.vsphere_tag_ids
  instances                   = var.num_instances
  cpu_number                  = var.num_cores[var.cores_count_type]
  ram_size                    = var.mem_size[var.mem_size_type]
  dc                          = var.vsphere_datacenter
  vmrp                        = data.vsphere_resource_pool.resource_pool.name
  vmfolder                    = var.vsphere_folder
  vmdomain                    = "local.domain"
  wait_for_guest_net_timeout  = 30
  wait_for_guest_net_routable = false

  ##Provisioning configurations
  remote_exec_command      = var.remote_exec_command
  remote_exec_user         = var.remote_exec_user
  remote_exec_ssh_key_file = var.remote_exec_ssh_key_file
  remote_exec_timeout      = var.remote_exec_timeout
  local_exec_user          = var.local_exec_user
  local_exec_ssh_key_file  = var.local_exec_ssh_key_file
  path_to_ansible          = var.path_to_ansible
  ansible_args             = format("--extra-vars '%#v' -e 'hostname=${var.name_prefix}-${count.index}' -e 'nomad_node_name=${var.name_prefix}-${count.index}' -e 'purpose=${var.nomad_purpose}' -e 'consul_acl_token=${var.consul_acl_token}' -e 'nomad_node_class=${var.nomad_node_class}' -e nomad_client_token='${var.nomad_consul_token}' -vvv -b", local.ansible_extra_vars)
}
