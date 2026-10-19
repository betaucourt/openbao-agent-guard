ui = true
default_lease_ttl = "15m"
max_lease_ttl = "1h"
cluster_addr = "https://127.0.0.1:8201"

storage "raft" {
  path = "/openbao/data"
  node_id = "openbao-local-node"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/run/secrets/openbao_tls_cert"
  tls_key_file = "/run/secrets/openbao_tls_key"
}

audit "file" "local-file" {
  description = "Persist local OpenBao audit records."
  options {
    file_path = "/openbao/audit/audit.log"
    mode = "0600"
  }
}
