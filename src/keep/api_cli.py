import os
import uvicorn

from keep.api_http import BoundedHttpToolsProtocol


def main():
    os.environ["KEEP_ROLE"] = "product-api"
    uvicorn.run("keep.main:app", host=os.getenv("KEEP_BIND_HOST", "127.0.0.1"),
                port=int(os.getenv("KEEP_BIND_PORT", "8000")),
                http=BoundedHttpToolsProtocol, proxy_headers=False, access_log=False)


if __name__ == "__main__":
    main()
