# HTTP Server with Authentication Project

## Overview
This project implements an HTTP server in Python that handles user authentication through username-password verification and manages user sessions using cookies. The server is designed to serve secret user data to authenticated users only, enhancing security through both client-side and server-side mechanisms.


## Features
- **User Authentication:** Authenticates users via HTTP POST requests containing username and password, ensuring that only valid users can access secret data.
- **Cookie Management:** Manages user sessions using cookies to maintain authentication state and enhance security.
- **Dynamic HTML Content:** Serves dynamic HTML pages based on the user's authentication status, including login forms, error messages, and secret data displays.

## Technologies Used
- **Programming Language:** Python
- **Libraries:** `socket`, `urllib.parse`, `datetime`, `signal`, `sys`, `random`

## Installation
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/jd1763/HTTP-Server.git
