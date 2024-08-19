#!/usr/bin/env python3


class AuthError(Exception):
    def __init__(self, *args, status=401, **kwargs):
        self.status = status

    @property
    def response(self):
        return {
            "status_code": self.status,
            "body": str(self),
        }
