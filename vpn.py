#!/usr/bin/env python3

import uvicorn
import QUIET_VPN

if __name__ == "__main__":
    config = uvicorn.Config("QUIET_VPN:app", port=8000, log_level="info")
    server = uvicorn.Server(config)
    server.run()
