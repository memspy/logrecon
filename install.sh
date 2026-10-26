[SERVICE]
    Flush        5
    Log_Level    info

[INPUT]
    Name            tail
    Path            /hostlogs/server.log
    Tag             server.log
    Read_from_Head  false
    DB              /fluent-bit/state/tail.db
    Skip_Long_Lines On
    Refresh_Interval 2

[OUTPUT]
    Name         http
    Match        server.log
    Host         ingest
    Port         8080
    URI          /fluentbit
    Format       json
