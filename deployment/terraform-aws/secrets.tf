# BYRLE_RP_KEY, which nginx sends and byrle checks. Generated as the database password is,
# and kept out of the state the same way.

ephemeral "random_password" "rp_key" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "rp_key" {
  name_prefix = "${var.name}-rp-key-"
}

resource "aws_secretsmanager_secret_version" "rp_key" {
  secret_id                = aws_secretsmanager_secret.rp_key.id
  secret_string_wo         = ephemeral.random_password.rp_key.result
  secret_string_wo_version = var.rp_key_version
}
