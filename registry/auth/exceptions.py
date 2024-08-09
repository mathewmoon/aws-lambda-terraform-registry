#!/usr/bin/env python3

class AuthError(Exception):
    def __init__(self, *args, status=401, **kwargs):
        self.status = status
        super().__init__(*args, **kwargs)

    @property
    def response(self):
        return {
            "status_code": self.status,
            "body": str(self),
        }