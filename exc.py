class AuthException(Exception):
    pass


class APIException(Exception):
    def __init__(
        self, message=None, status_code=None, errors=None, url=None, method=None
    ):
        if errors and not message:
            message = json.dumps(errors)
        super(APIException, self).__init__(message)
        self.message = message
        self.status_code = status_code
        self.errors = errors or []
        self.url = url
        self.method = method

    @property
    def human_str(self):
        return (
            "API Error: {msg:s}\n{method:s}: {url:s}\nHTTP Status: {status}\nError Detail:\n{"
            "detail}"
        ).format(
            msg=self.__str__(),
            status=self.status_code or "[unknown]",
            detail=json.dumps(self.errors, sort_keys=True, indent=2),
            method="HTTP {}".format(self.method or "[unknown method]"),
            url=self.url or "[URL unknown]",
        )
