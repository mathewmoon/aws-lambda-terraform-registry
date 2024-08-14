data "aws_kms_key" "this" {
  key_id = "alias/jwt"
}

data "aws_kms_public_key" "jwt_signer" {
  key_id = data.aws_kms_key.this.key_id
}

data "jwks_from_key" "jwt_signer" {
  key = data.aws_kms_public_key.jwt_signer.public_key
}

resource "local_file" "jwks" {
  content = templatefile(
    "${path.module}/jwks.tftpl",
    {
      jwks = data.jwks_from_key.jwt_signer.jwks
    }
  )
  filename = "${path.module}/jwks.py"
}
