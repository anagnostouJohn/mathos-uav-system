Airborne Gateway
    Talks to the FC through MAVLink.
    Sends telemetry to the main RC.
    Receives control commands from the RC.

Main RC ESP32
    Handles controls, safety, display, and the primary aircraft link.
    Receives telemetry from the aircraft.
    Forwards selected telemetry locally to the second ESP32.

RC Telemetry-Relay ESP32
    Physically installed in or connected to the RC.
    Receives telemetry from the main RC over UART or SPI.
    Transmits that telemetry using a completely separate RF link.
    Does not need to contact the API directly.
    
Remote Ground Gateway ESP32
    Located far away from the pilot.
    Receives the secondary RF telemetry stream.
    Connects to the internet or local network.
    Sends telemetry to the API/server.




“where are we?”, “what is next?”, or “show the backlog”,