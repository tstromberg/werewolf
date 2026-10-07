# OpenBao's configuration beyond what the settings fill (config.json),
# for the openbao form (docs/openbao.md), in HCL since that is how OpenBao
# documents these stanzas.
#
# Every request is a line on the console: the stdout audit device,
# declared here rather than enabled over the API, so no one can disable
# it without a new image.
audit "file" "stdout" {
  description = "every request, on the console"
  options {
    file_path = "stdout"
    log_raw = "true"
  }
}

# The first start: what `bao operator init` and the first logins would
# do, done by OpenBao itself under its static seal, once, then the root
# token revoked. An admin, who may do everything, logging in by userpass
# with the password whose bcrypt hash the config brought
# (/run/config/openbao/admin_password_hash; leash's copy is read here).
initialize "admin" {
  request "policy" {
    operation = "update"
    path      = "sys/policies/acl/admin"
    data = {
      policy = "path \"*\" { capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"patch\", \"scan\", \"sudo\"] }"
    }
  }
  request "userpass" {
    operation = "update"
    path      = "sys/auth/userpass"
    data = {
      type = "userpass"
    }
  }
  request "admin-user" {
    operation = "update"
    path      = "auth/userpass/users/admin"
    data = {
      password_hash = {
        eval_type   = "string"
        eval_source = "file"
        path        = "/run/svc/openbao/admin-password-hash"
      }
      token_policies = ["admin"]
    }
  }
}
