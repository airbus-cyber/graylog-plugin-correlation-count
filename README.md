# Correlation Count Plugin for Graylog

[![Build Status](https://travis-ci.org/airbus-cyber/graylog-plugin-correlation-count.svg?branch=develop)](https://travis-ci.org/airbus-cyber/graylog-plugin-correlation-count)
[![License](https://img.shields.io/badge/license-GPL--3.0-orange.svg)](https://www.gnu.org/licenses/gpl-3.0.txt)
[![GitHub Release](https://img.shields.io/badge/release-v0.3.1-blue.svg)](https://github.com/airbus-cyber/graylog-plugin-correlation-count/releases)

#### Alert condition plugin for Graylog to perform correlation

The alert condition triggers whenever the main stream received more or less than X messages and the additional stream received more or less than Y messages in the last Z minutes.

This is useful for correlating messages of different kinds.

Perfect for example to be alerted when there is a successful authentication after a number of authentication attempts on your platform. Create a stream that catches every authentification failure and another stream that catches every successful authentification and be alerted when the first one exceeds a given threshold and the second one exceeds another given threshold (here zero) per user.

Please also take note that only a single alert is raised for this condition during the alerting interval, although multiple messages containing different values for the message fields may have been received since the last alert.

**Required Graylog version:** 2.4.3 and later

Example of raised alert:

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-correlation-count/develop/images/alert.png)

## Installation

[Download the plugin](https://.../graylog2-plugin-correlation-count/tree/master/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

## Usage

First you have to select the **Main Stream** and the alert type **Correlation Count Alert Condition**

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-correlation-count/develop/images/select_condition.png)

Then, in the popup that occurs, you can configure the **Additional Stream** to correlate messages of different kind from the main stream.

The parameters **Additional Threshold** and **Additional Threshold Type** let you respectively select the threshold and its type which apply on the additional stream.

Similarly, the parameters **Main Threshold** and **Main Threshold Type** let you respectively select the threshold and its type which apply on the main stream.

You can configure the **Messages Order** between the additional stream and the main stream if you want for example the messages of the additional stream to precede the messages of the main stream to trigger the alert.

You can optionally configure the **Grouping Fields** to only count messages with the same values in both streams.

You can also set all the common parameters : **Title**, **Time Range**, **Grace Period**, **Message Backlog** and **Repeat notifications**.

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-correlation-count/develop/images/edit_condition.png)

Click on **Manage conditions** in the **Alerts** section to see the conditions details.

## Build

This project is using Maven 3 and requires Java 8 or higher.

* Clone this repository.
* Run `mvn package` to build a JAR file.
* Optional: Run `mvn jdeb:jdeb` and `mvn rpm:rpm` to create a DEB and RPM package respectively.
* Copy generated JAR file in target directory to your Graylog plugin directory.
* Restart the Graylog.

## License

This plugin is released under version 3.0 of the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.txt).
