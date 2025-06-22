"""Custom Tuya BLE DP mappings."""

from dataclasses import dataclass
from .devices import DPMapping  # import your base DPMapping class

@dataclass
class TuyaBLETemperatureMapping(DPMapping):
    """Specialized mapping for temperature sensors."""
    pass

@dataclass
class TuyaBLEHumidityMapping(DPMapping):
    """Specialized mapping for humidity sensors."""
    pass

@dataclass
class TuyaBLEBatteryMapping(DPMapping):
    """Specialized mapping for battery sensors."""
    pass

@dataclass
class TuyaBLEDiagnosticMapping(DPMapping):
    """Mapping for diagnostic data like signal strength."""
    pass
