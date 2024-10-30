# Correlation Count Plugin for Graylog

[![Continuous Integration](https://github.com/airbus-cyber/graylog-plugin-correlation-count/actions/workflows/ci.yml/badge.svg)](https://github.com/airbus-cyber/graylog-plugin-correlation-count/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-SSPL-green)](https://www.mongodb.com/licensing/server-side-public-license)
[![GitHub Release](https://img.shields.io/github/v/release/airbus-cyber/graylog-plugin-correlation-count)](https://github.com/airbus-cyber/graylog-plugin-correlation-count/releases)

#### Alert condition plugin for Graylog to perform correlation

The alert condition triggers whenever the main stream received more or less than X messages and the additional stream received more or less than Y messages in the last Z minutes.

This is useful for correlating messages of different kinds.

Perfect for example to be alerted when there is a successful authentication after a number of authentication attempts on your platform. Create a stream that catches every authentification failure and another stream that catches every successful authentification and be alerted when the first one exceeds a given threshold and the second one exceeds another given threshold (here zero) per user.

Please also take note that only a single alert is raised for this condition during the alerting interval, although multiple messages containing different values for the message fields may have been received since the last alert.

Example of raised alert:

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-correlation-count/master/images/alert.png)

## Version Compatibility

| Plugin Version | Graylog Version |
|----------------|-----------------|
| 6.1.x          | 6.1.x           |
| 6.0.x          | 6.0.x           |
| 5.1.x          | 5.1.x           |
| 5.0.x          | 5.0.x           |
| 4.2.x          | 4.3.x           |
| 4.1.x          | 4.2.x           |
| 4.0.x          | 4.1.x           |
| 2.2.x          | 3.3.x           |
| 2.1.x          | 3.2.x           |
| 2.0.x          | 3.2.x           |
| 1.2.x          | 3.0.x           |
| 1.1.x          | 2.5.x           |
| 1.0.x          | 2.4.x           |


## Installation

[Download the plugin](https://github.com/airbus-cyber/graylog-plugin-correlation-count/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

## Usage

First you have to select the alert type **Correlation Count Alert Condition**

Then, you can configure the **Stream**. The parameters **Threshold** and **Threshold Type** let you respectively select the threshold and its type which apply on the main stream.

Similarly, you can configure the **Additional Stream** to correlate messages of different kind from the main stream.

The parameters **Additional Threshold** and **Additional Threshold Type** let you respectively select the threshold and its type which apply on the additional stream.

You can configure the **Messages Order** between the additional stream and the main stream if you want for example the messages of the additional stream to precede the messages of the main stream to trigger the alert.

You can optionally configure the **Grouping Fields** to only count messages with the same values in both streams.

You can also set all the common parameters : **Search within the last**, **Execute search every** and **Search Query**.

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-correlation-count/master/images/edit_condition.png)

## Build

This project is using Maven 3 and requires Java 8 or higher.

* Clone this repository.
* Run `mvn package` to build a JAR file.
* Optional: Run `mvn jdeb:jdeb` and `mvn rpm:rpm` to create a DEB and RPM package respectively.
* Copy generated JAR file in target directory to your Graylog plugin directory.
* Restart the Graylog.

## License

This plugin is released under version 1 of the [Server Side Public License (SSPL)](LICENSE).
