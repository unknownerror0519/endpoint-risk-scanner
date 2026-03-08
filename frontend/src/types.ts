export type ScanStatus = 'not_scanned' | 'scanning' | 'completed' | 'failed'

export type CveDetail = {
  cve_id: string
  published?: string | null
  description?: string | null
  cwe?: string | null
  match_source?: string | null
  version_match?: string | null
  match_confidence?: string | null
  cvss_v3?: {
    version?: string
    vectorString?: string
    baseScore?: number
    baseSeverity?: string
  } | null
  references?: string[]
  matched_cpe?: string | null
  kev_flag?: boolean
  kev_date_added?: string | null
  epss?: number | null
  epss_percentile?: number | null
  vulners_exploit_flag?: boolean
  exploitdb_flag?: boolean
  ml_probability?: number | null
  ml_exploit_probability?: number | null
  cvss_severity_norm?: number | null
  final_cve_risk?: number | null
  final_cve_risk_0_100?: number | null
  risk_tier?: string | null
}

export type ApplicationCves = {
  display_product: string
  vendor_normalized?: string | null
  product_normalized?: string | null
  version_normalized?: string | null
  matched_cve_count: number
  matched_cves: CveDetail[]
}

export type EndpointListItem = {
  endpoint_id: string
  endpoint_name?: string | null
  scan_status: ScanStatus
  last_scanned_at?: string | null
  endpoint_risk_score_0_100?: number | null
  endpoint_risk_tier?: string | null
  os_name?: string | null
  is_online?: boolean | null
  last_seen?: string | null
  application_count: number
}

export type ApplicationSummary = {
  display_product: string
  vendor_normalized?: string | null
  product_normalized?: string | null
  version_normalized?: string | null
  matched_cve_count: number
  application_risk_score_0_100?: number | null
  application_risk_tier?: string | null
  kev_cve_count: number
  exploit_evidence_count: number
}

export type EndpointResults = {
  endpoint_id: string
  scan_status: ScanStatus
  last_scanned_at?: string | null
  endpoint_summary?: Record<string, unknown> | null
  application_summaries: ApplicationSummary[]
  error_message?: string | null
}

// Full endpoint document from Firestore
export type EndpointDetail = {
  endpoint_id: string
  scan_status?: ScanStatus
  endpoint_name?: string | null
  agent_version?: string | null
  first_seen?: string | null
  last_updated?: string | null
  collection_timestamp?: string | null
  connection_status?: {
    online?: boolean
    hostname?: string
    last_seen?: string
  } | null
  identity?: {
    hostname?: string
    device_uuid?: string
    uptime?: string
    last_boot_time?: string
    timestamp?: string
  } | null
  system?: {
    os_name?: string
    os_version?: string
    os_build?: string
    os_architecture?: string
    os_manufacturer?: string
    cpu?: Array<{ name?: string; cores?: number; logical_processors?: number; max_clock_speed?: string }>
    memory?: { total_gb?: number; used_gb?: number; available_gb?: number; percent_used?: number }
    disks?: Array<{ device?: string; mountpoint?: string; filesystem?: string; total_gb?: number; used_gb?: number; free_gb?: number; percent_used?: number }>
    storage?: Array<{ model?: string; serial?: string; size_gib?: number; partitions?: string[] }>
    hardware_serials?: { system?: string; bios?: string; motherboard?: string; disks?: Array<{ model?: string; serial?: string; size_gb?: number }> }
    ram_total_gib?: number
    ram_sticks?: Array<Record<string, unknown>>
    cpu_usage_percent?: number
  } | null
  network?: {
    public_ip?: string
    active_connections?: Array<{ process?: string; remote_address?: string; status?: string; local_address?: string; pid?: number }>
    listening_ports?: Array<{ process?: string; protocol?: string; pid?: number; port?: number }>
    dns_servers?: string[]
    interfaces?: Array<{ name?: string; mac?: string; ipv4?: string }>
  } | null
  security?: {
    antivirus?: Array<{ name?: string; enabled?: boolean; updated?: boolean; state?: string }>
    firewall?: Array<{ name?: string; enabled?: boolean; state?: string }>
    windows_firewall?: Record<string, string>
    bitlocker?: Array<{ drive?: string; protection_status?: number }>
    uac_enabled?: boolean
    windows_defender?: { realtime_protection?: boolean; antivirus_enabled?: boolean; antispyware_enabled?: boolean; signature_updated?: string | null }
  } | null
  users?: Array<{ name?: string; disabled?: boolean; lockout?: boolean; full_name?: string; password_expires?: boolean; password_required?: boolean; sid?: string; password_changeable?: boolean }> | null
  windows_updates?: { pending_updates?: number; last_boot?: string } | null
  applications?: Array<{ name?: string; version?: string; publisher?: string; install_location?: string; install_date?: string }> | null
  startup_programs?: Array<{ name?: string; command?: string; location?: string }> | null
  processes?: Array<{ pid?: number; name?: string; status?: string; memory_percent?: number; user?: string }> | null
  scheduled_tasks?: Array<{ name?: string; status?: string }> | null
  prefetch_files?: Array<{ filename?: string; size_kb?: number; modified?: string }> | null
  usb_history?: Array<{ device?: string; instance?: string }> | null
  [key: string]: unknown
}
