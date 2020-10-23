/*
 * graylog-plugin-correlation-count Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-correlation-count GPL Source Code.
 *
 * graylog-plugin-correlation-count Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.airbus_cyber_security.graylog.events.processor.correlation.checks;

public class Threshold {

    private final ThresholdType type;
    private final int value;

    public Threshold(String type, int value) {
        this.type = ThresholdType.fromString(type);
        this.value = value;
    }

    public boolean isReached(long count) {
        return (((this.type == ThresholdType.MORE) && (count > this.value)) ||
                ((this.type == ThresholdType.LESS) && (count < this.value)));
    }
}
