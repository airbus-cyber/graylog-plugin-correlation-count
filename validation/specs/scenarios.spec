# End-to-end test scenarios

To execute this specification, build the plugin jar and copy it to execution_environment/graylog/plugin, then run

    gauge specs


## Plugin should not fail on receiving a message

* Start Graylog server
* Login as "admin"/"admin"
* Stop Graylog server

