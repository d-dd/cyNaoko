﻿#!/usr/bin/env python
# Contains settings that are relevant in multiple places but should not be changed outside of special circumstances

import logging

# Default timeout for both the monitoring process and the heartbeat thread
TIMEOUT = 35

# The logging level, choose between logging.DEBUG, logging.INFO, logging.WARNING, and logging.ERROR.
# It is recommended to use a setting of WARNING or lower.
LOG_LEVEL = logging.DEBUG

# Default wait when an unknown video is playing in seconds.
DEFAULT_WAIT = 3 * 60 * 60

# The minimum time, in seconds, between storing the count of users in the room.
# Only increase this if she is logging too often in a busy room and wasting too much space.
USER_COUNT_THROTTLE = 0

# The time between status checks in seconds.
HEARTBEAT_CHECK = 5

# The minimum time between API requests in seconds
API_THROTTLE = 0.5

# Countries a video must be able to play in
REQUIRED_COUNTRIES = set(["CA", "US"])

# Custom user agent for VocaDB API requests. Leave empty to disable.
# Only fill this if the channel is strictly for viewing Vocaloid related media. 
# e.g. {"User-agent": "d-dd/cyNaoko (CyTube; username; url)"}
VDB_USER_AGENT = {}

# Link to VocaDB Help File
VDB_README_URL = "https://github.com/d-dd/cyNaoko/blob/master/README.md#VocaDB"
