# Change Log

All notable changes to this project will be documented in this file.

## [4.2.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/4.1.3...4.2.0)
### Features
* Add compatibility with [Graylog 4.3](https://www.graylog.org/post/announcing-graylog-v4-3-graylog-operations-graylog-security)

## [4.1.3](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/4.1.2...4.1.3)
### Bug Fixes
* A grouping field with a special character such as space was not working. The values of grouping fields are now escaped in search queries ([issue 27](https://github.com/airbus-cyber/graylog-plugin-correlation-count/issues/27))

## [4.1.2](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/4.1.1...4.1.2)
### Bug Fixes
* Correct handling of catchup windows. There is no more exception on several results with the same grouping field value
  (see Alert Wizard plugin [issue 60](https://github.com/airbus-cyber/graylog-plugin-alert-wizard/issues/60))

## [4.1.1](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/4.1.0...4.1.1)
### Bug Fixes
* Log an error instead of raising an exception when there are several results with the same grouping field
  values (see Alert Wizard plugin [issue 60](https://github.com/airbus-cyber/graylog-plugin-alert-wizard/issues/60))

## [4.1.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/4.0.1...4.1.0)
### Features
* Add compatibility with Graylog 4.2

## [4.0.1](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/4.0.0...4.0.1)
### Bug Fixes
* Put back missing jar in release page of github thanks to a continuous integration based on github actions

## [4.0.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/2.2.0...4.0.0)
### Features
* Add compatibility with Graylog 4.1
* Change plugin license to SSPL version 1

## [2.2.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/2.1.2...2.2.0)
### Features
* Add compatibility with Graylog 3.3

## [2.1.2](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/2.1.1...2.1.2)
### Bug Fixes
* Fix Create only 1 event when the condition is satisfied

## [2.1.1](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/2.1.0...2.1.1)
### Bug Fixes
* Fix event source streams empty

## [2.1.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/2.0.0...2.1.0)
### Features
* Disabled isolated Plugin (shares a class loader with other plugins that have isolated=false)

## [2.0.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/1.2.0...2.0.0)
### Features
* Add compatibility with Graylog 3.2

## [1.2.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/1.1.0...1.2.0)
### Features
* Add compatibility with Graylog 3.0

## [1.1.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/1.0.1...1.1.0)
### Features
* Add the Search Query functionality for compatibility with Graylog 2.5

## [1.0.1](https://github.com/airbus-cyber/graylog-plugin-correlation-count/compare/1.0.0...1.0.1)
### Bug Fixes
* Fix the graphic display of the messages order to clarify this order

## [1.0.0](https://github.com/airbus-cyber/graylog-plugin-correlation-count/tree/1.0.0)
* First release
