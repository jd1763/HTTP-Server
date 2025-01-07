import socket
import signal
import sys
import random
import urllib.parse
from datetime import datetime, timedelta, timezone

# Define global dictionaries for user data
user_passwords = {}  # Dictionary to store username:password pairs
user_secrets = {}  # Dictionary to store username:secret pairs
 # Global dictionary to store active session cookies and their associated usernames
active_sessions = {}


# Function to load user data from files
def load_user_data():
    # Read usernames and passwords from passwords.txt    
    with open('passwords.txt', 'r') as file:
        for line in file:
            if line.strip(): # Ensure the line is not empty
                username, password = line.strip().split()
                user_passwords[username] = password # Store username-password data

    # Read usernames and secrets from secrets.txt
    with open('secrets.txt', 'r') as file:
        for line in file:
            if line.strip(): # Ensure the line is not empty
                username, secret = line.strip().split()
                user_secrets[username] = secret # Store username-secret data


# Helper function to parse POST data from the HTTP request body
def parse_post_data(data):
    post_data = {} # Dictionary that will hold post data
    if data:
        # Split the data by '&' to separate key-value pairs
        parts = data.split('&')
        for part in parts:
            # Split each part by '=' to seperate the keys from the values
            key, value = part.split('=')
            # Decode the value from URL encoding to plain text
            post_data[key] = urllib.parse.unquote(value)
    return post_data

# Helper function to extract cookies from the requests headers
def extract_cookie(headers):
    # This function will parse the headers to find the cookie
    for header in headers.split('\r\n'):
        if header.startswith('Cookie:'):
            try:
                # Assuming the cookie format is "Cookie: session_id=value"
                cookie_value = header.split(' ')[1].split('=')[1]
                return cookie_value
            except IndexError:
                # In case the cookie is malformed or the split fails
                print("Failed to extract cookie")
                return None
    return None


# Function to format the cookie expiration date for HTTP headers
def format_http_date(expires):
    weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
             "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    # Format date in HTTP standard format
    return "{}, {:02d} {} {:04d} {:02d}:{:02d}:{:02d} GMT".format(
        weekday[expires.weekday()], expires.day, month[expires.month - 1],
        expires.year, expires.hour, expires.minute, expires.second)

# Function to get expiration for cookies (default 24 hours from now)
def get_expiration(hours=24):
    expires = datetime.now(tz=timezone.utc) + timedelta(hours=hours)
    return format_http_date(expires)


def serv(hostname, port):
    # Start a listening server socket on the port (Create a TCP socket)
    sock = socket.socket()
    sock.bind(('', port)) # Bind the socket to the port
    sock.listen(2) # Listen for incoming connections (maximum of 2 queued connections)
    
    # Signal handler for graceful exit (shutting down the server on a SIGINT (Ctrl+C))
    def sigint_handler(sig, frame):
        print('Finishing up by closing listening socket...')
        sock.close()
        sys.exit(0)

    # Register the signal handler
    signal.signal(signal.SIGINT, sigint_handler)

    ### Contents of pages we will serve. (HTML templates for different responses)
    # Login form HTML that will be inserted into various pages
    login_form = """
    <form action = "http://%s" method = "post">
    Name: <input type = "text" name = "username">  <br/>
    Password: <input type = "text" name = "password" /> <br/>
    <input type = "submit" value = "Submit" />
    </form>
    """

    # Default page: Login page (prompts user to log in)
    login_page = "<h1>Please login</h1>" + login_form
    # Error page for bad credentials (shown if username or password is incorrect)
    bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
    # Successful logout (shown after user logs out)
    logout_page = "<h1>Logged out successfully</h1>" + login_form
    # A part of the page that will be displayed after successful
    # login or the presentation of a valid cookie
    success_page = """
    <h1>Welcome!</h1>
    <form action="http://%s" method = "post">
    <input type = "hidden" name = "action" value = "logout" />
    <input type = "submit" value = "Click here to logout" />
    </form>
    <br/><br/>
    <h1>Your secret data is here:</h1>
    """

    #### Helper functions
    # Printing. (values in a readable format)
    def print_value(tag, value):
        print("Here is the", tag)
        print("\"\"\"")
        print(value)
        print("\"\"\"")
        print()

    ## Function to load user data from files
    load_user_data()

    ### Main Loop to accept and handle incoming resquest(HTTP connections and respond)
    while True:
        client, addr = sock.accept() # Accept a new connection
        req = client.recv(1024) # Receive the data sent by the client

        # Parse the HTTP request to seperate the headers and entity body apart
        header_body = req.decode().split('\r\n\r\n')
        headers = header_body[0] # HTTP headers part
        body = '' if len(header_body) == 1 else header_body[1] # HTTP body part
        print_value('headers', headers)
        print_value('entity body', body)

        ## Determine the host and port for the form's submit URL
        submit_hostport = "%s:%d" % (hostname, port)
        # Initialize default response
        response = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Unhandled Request Type</h1>'

        # (2) `headers_to_send` => add any additional headers
        # you'd like to send the client?
        # Right now, we don't send any extra headers.
        headers_to_send = ''

        try:

            # Check for cookies in the request
            cookie_value = extract_cookie(headers)

            ## Parse POST data if present
            post_data = parse_post_data(body)
            
            # Handle logout request
            if 'action' in post_data and post_data['action'] == 'logout':
                if cookie_value in active_sessions:
                    del active_sessions[cookie_value] # Remove session from active_sessions
                # This sends a cookie with an expiration date in the past, instructing the browser to delete it.
                response = f'HTTP/1.1 200 OK\r\nSet-Cookie: token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/\r\nContent-Type: text/html\r\n\r\n' + logout_page % submit_hostport
            # Cookie validated
            elif cookie_value and cookie_value in active_sessions:
                username = active_sessions[cookie_value]
                secret = user_secrets.get(username, 'No secret available for this user')
                html_content_to_send = (success_page % submit_hostport) + secret
                response = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + html_content_to_send
            # Cookie invalid
            elif cookie_value and cookie_value not in active_sessions:
                # No valid cookie found, send back bad_creds_page
                html_content_to_send = bad_creds_page % submit_hostport
                response = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + html_content_to_send
            # Determine response based on POST data
            elif 'username' in post_data and 'password' in post_data:
                username = post_data['username']
                password = post_data['password']
                
                # Check if username and password match the records
                # Username-password auth success
                if username in user_passwords and user_passwords[username] == password:
                    # Authentication successful
                    # Generates a random 64-bit integer and converts it to a string
                    cookie_value = str(random.getrandbits(64))
                    # Store the cookie with the username for session management
                    active_sessions[cookie_value] = username

                    # Get the secret data associated with the username
                    # (second parameter is a default value in case there's no secret for set username)
                    secret = user_secrets.get(username, 'No secret available for this user')
                    # Set HTML content to success page and append the user's secret
                    html_content_to_send = (success_page % submit_hostport) + secret
                    cookie_header = f'Set-Cookie: token={cookie_value}; Path=/; Expires={get_expiration()}; HttpOnly; Secure'
                    response = f'HTTP/1.1 200 OK\r\n{cookie_header}\r\nContent-Type: text/html\r\n\r\n' + html_content_to_send
                # Username-password auth failure
                else: 
                    # Authentication failed due to incorrect password or username
                    html_content_to_send = bad_creds_page % submit_hostport
                    response = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + html_content_to_send
            else:
                # Default response for when there's no POST data provided or it's incomplete
                html_content_to_send = login_page % submit_hostport
                response = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + html_content_to_send

        except Exception as e:
            print("Error processing request:", str(e))
            response = 'HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<h1>Internal Server Error</h1>'

        print_value('response', response)
        
        client.send(response.encode()) # Send the response to the client
        client.close() # Close the client connection
        req=None
        print("Served one request/connection!\n")

if __name__ == "__main__":
    # Read a command line argument for the port where the server
    # must run.
    port = 8080 # Default port
    if len(sys.argv) == 2:
        try:
            port = int(sys.argv[1]) # If a port is provided as an argument, use it
            print(f"Using given port: {int(sys.argv[1])}")
        except:
            print("Invalid Port Error")
            sys.exit(1)
    elif len(sys.argv) == 1:
        print("Using default port: 8080")
    else:
        print(f"Invalid Call Error, Size:{len(sys.argv)}")
        sys.exit(1)
    hostname = "localhost" 
    serv(hostname, port)

# We will never actually get here.
# Close the listening socket
#sock.close()
