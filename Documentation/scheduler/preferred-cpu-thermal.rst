.. SPDX-License-Identifier: GPL-2.0

Thermal control with preferred CPUs
===================================

Preferred CPU selection can be driven by thermal signal. A userspace thermal
policy can reduce the preferred CPU set to concentrate fair tasks on fewer
CPUs, allowing other CPUs to become idle. This approach may be preferred over
offlining CPUs because it preserves tasks affinity and has lower system
overhead.

The following thermald configuration illustrates this on a system with two
online CPUs. CPU0 stays preferred. When the package temperature reaches 80 C,
CPU1 becomes non-preferred. Once the temperature falls below 75 C, CPU1
becomes preferred again.

Save the configuration as ``/etc/thermald/thermal-conf-preferred.xml``.
Replace the sensor path with the package temperature sensor on the target
system: the example assumes ``thermal_zone0/type`` is ``x86_pkg_temp``.
Temperature and hysteresis values are in millidegrees Celsius::

    <?xml version="1.0"?>
    <ThermalConfiguration>
      <Platform>
        <Name>Preferred CPU thermal policy</Name>
        <ProductName>*</ProductName>
        <Preference>QUIET</Preference>
        <ThermalSensors>
          <ThermalSensor>
            <Type>package-temperature</Type>
            <Path>/sys/class/thermal/thermal_zone0/temp</Path>
            <AsyncCapable>0</AsyncCapable>
          </ThermalSensor>
        </ThermalSensors>
        <ThermalZones>
          <ThermalZone>
            <Type>preferred-cpu-zone</Type>
            <TripPoints>
              <TripPoint>
                <SensorType>package-temperature</SensorType>
                <Temperature>80000</Temperature>
                <Hyst>5000</Hyst>
                <type>passive</type>
                <ControlType>PARALLEL</ControlType>
                <CoolingDevice>
                  <type>preferred-cpu1</type>
                  <TargetState>0</TargetState>
                </CoolingDevice>
              </TripPoint>
            </TripPoints>
          </ThermalZone>
        </ThermalZones>
        <CoolingDevices>
          <CoolingDevice>
            <Type>preferred-cpu0</Type>
            <Path>/sys/devices/system/cpu/cpu0/preferred</Path>
            <MinState>1</MinState>
            <MaxState>1</MaxState>
            <ReadBack>1</ReadBack>
          </CoolingDevice>
          <CoolingDevice>
            <Type>preferred-cpu1</Type>
            <Path>/sys/devices/system/cpu/cpu1/preferred</Path>
            <MinState>1</MinState>
            <MaxState>0</MaxState>
            <ReadBack>1</ReadBack>
          </CoolingDevice>
        </CoolingDevices>
      </Platform>
    </ThermalConfiguration>

CPU0 is declared with both states set to 1 and has no associated trip, so
thermald does not change its preferred status. Keep CPU0 preferred to ensure
that at least one CPU remains preferred.

CPU1's cooling states are deliberately reversed: ``MinState=1`` is the
normal preferred state, and ``MaxState=0`` is the cooling state.
``TargetState=0`` explicitly clears CPU1's preferred status when the trip
is active. When the trip clears, thermald restores ``MinState=1``.

Usage.

Stop any existing thermald service, then run this example as root::

    thermald --no-daemon --ignore-default-control --poll-interval=1 \
        --config-file=/etc/thermald/thermal-conf-preferred.xml

On SMT systems, control all siblings of a core together when the goal is to
idle a whole core. CPU hotplug can change the preferred mask independently
of thermald.

See :ref:`sched-paravirt` for scheduling behavior and
``Documentation/ABI/testing/sysfs-devices-system-cpu-preferred`` for the
sysfs interface and hotplug rules.
