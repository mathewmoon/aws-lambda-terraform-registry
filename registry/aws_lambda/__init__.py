from json import dumps

def make_lambda_response(
  status: int,
  body: str = "",
  headers: dict[str, str] = {}
):
    return {
      "isBase64Encoded" : False,
      "statusCode": status,
      "headers": headers,
      "body": dumps(body)
    }
