from cloudlink import server
from cloudlink.server.protocols import clpv4


if __name__ == "__main__":
    # Initialize the server
    server = server()
    
    # Configure logging settings
    server.logging.basicConfig(
        level=server.logging.DEBUG
    )

    # Load protocols
    clpv4 = clpv4(server)
    
    # Initialize SSL support
    # server.enable_ssl(certfile="cert.pem", keyfile="privkey.pem")
    
    # Start the server
    server.run(ip="127.0.0.1", port=3000)
