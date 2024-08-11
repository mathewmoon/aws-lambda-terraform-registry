def parse_assumed_role(role_arn):
    """
    Handles parsing of assumed role ARNs to IAM role ARNs.
    """
    role_arn_with_session = role_arn.replace(":sts:", ":iam:").replace(
        ":assumed-role/", ":role/"
    )
    role_parts = role_arn_with_session.split("/")
    role_parts.pop(-1)

    if role_parts[-1].startswith("AWSReservedSSO_"):
        print("SSO")
        role_parts[-1] = f"aws-reserved/sso.amazonaws.com/{role_parts[-1]}"

    role_arn = "/".join(role_parts)

    return role_arn
