"""Process-owned Elasticsearch transport with per-request deadline options."""

from appchi.request_budget import remaining
from appchi.shared.errors import unavailable


def search_client(request):
    client = getattr(request.app.state, "search_client", None)
    if client is None:
        raise unavailable("search_not_ready")
    return BudgetSearchClient(client)


class BudgetSearchClient:
    def __init__(self, client, timeout=5):
        self.client = client
        self.timeout = timeout

    def options(self, **kwargs):
        timeout = min(self.timeout, kwargs.get("request_timeout", self.timeout))
        kwargs["request_timeout"] = remaining(timeout)
        return BudgetSearchClient(self.client.options(**kwargs), timeout)

    def __getattr__(self, name):
        def call(**kwargs):
            return getattr(
                self.client.options(request_timeout=remaining(self.timeout), max_retries=0), name
            )(**kwargs)

        return call
