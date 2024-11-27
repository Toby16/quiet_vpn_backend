#!/usr/bin/env python3

import uvicorn
import QUIET

if __name__ == "__main__":
    config = uvicorn.Config("QUIET:app", port=8000, log_level="info")
    server = uvicorn.Server(config)
    server.run()
