[SERVICE]
    Flush        5
    Log_Level    info

[INPUT]
    Name            tail
    Path            /absolute/path/to/logs/server.log
    Tag             server.log
    Read_from_Head  false

[OUTPUT]
    Name         http
    Match        server.log
    Host         127.0.0.1
    Port         8080
    URI          /fluentbit
    Format       json
