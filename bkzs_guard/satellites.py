from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SatelliteProfile:
    profile_id: str
    satellite_name: str
    mission_domain: str
    operator: str
    launch_year: int | None
    orbit_type: str
    orbital_slot_deg_e: float | None = None
    altitude_km: float | None = None
    allowed_channels: tuple[str, ...] = ()
    allowed_uplink_bands: tuple[str, ...] = ()
    allowed_downlink_bands: tuple[str, ...] = ()
    allowed_tmtc_bands: tuple[str, ...] = ()
    allowed_protocols: tuple[str, ...] = ()
    allowed_transponder_bandwidths_mhz: tuple[int, ...] = ()
    sensor_type: str | None = None
    resolution_hint: str | None = None
    coverage_hint: str = ""
    public_note: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)

    @property
    def primary_channel(self) -> str:
        return self.allowed_channels[0] if self.allowed_channels else "bkzs-nav"

    @property
    def display_name(self) -> str:
        return self.satellite_name


SATELLITE_PROFILES: dict[str, SatelliteProfile] = {
    "generic-bkzs": SatelliteProfile(
        profile_id="generic-bkzs",
        satellite_name="BKZS Generic",
        mission_domain="generic",
        operator="Demo",
        launch_year=None,
        orbit_type="GENERIC",
        allowed_channels=("bkzs-nav",),
        public_note="Generic profile for backward compatibility.",
    ),
    "turksat-3a": SatelliteProfile(
        profile_id="turksat-3a",
        satellite_name="Turksat 3A",
        mission_domain="communications",
        operator="Turksat",
        launch_year=2008,
        orbit_type="GEO",
        orbital_slot_deg_e=42.0,
        allowed_channels=("satcom-relay", "broadcast", "telemetry"),
        allowed_uplink_bands=("Ku-Band",),
        allowed_downlink_bands=("Ku-Band",),
        allowed_protocols=("transponder-metadata", "broadcast-monitor"),
        allowed_transponder_bandwidths_mhz=(36, 72),
        coverage_hint="East, West",
        public_note="42E GEO Ku-band communications satellite with 36/72 MHz transponders.",
        aliases=("Türksat 3A",),
    ),
    "turksat-4a": SatelliteProfile(
        profile_id="turksat-4a",
        satellite_name="Turksat 4A",
        mission_domain="communications",
        operator="Turksat",
        launch_year=2014,
        orbit_type="GEO",
        orbital_slot_deg_e=42.0,
        allowed_channels=("satcom-relay", "broadcast", "telemetry"),
        allowed_uplink_bands=("Ku-Band", "Ku-BSS Band", "Ka-Band"),
        allowed_downlink_bands=("Ku-Band", "Ku-BSS Band", "Ka-Band"),
        allowed_protocols=("transponder-metadata", "broadcast-monitor"),
        allowed_transponder_bandwidths_mhz=(27, 33, 54, 72),
        coverage_hint="Turkey, East, West, Africa",
        public_note="42E GEO communications satellite with Ku, Ku-BSS and Ka capacity.",
        aliases=("Türksat 4A",),
    ),
    "turksat-4b": SatelliteProfile(
        profile_id="turksat-4b",
        satellite_name="Turksat 4B",
        mission_domain="communications",
        operator="Turksat",
        launch_year=2015,
        orbit_type="GEO",
        orbital_slot_deg_e=50.0,
        allowed_channels=("satcom-relay", "broadband", "telemetry"),
        allowed_uplink_bands=("Ku-Band", "Ka-Band", "C-Band"),
        allowed_downlink_bands=("Ku-Band", "Ka-Band", "C-Band"),
        allowed_protocols=("transponder-metadata", "broadband-monitor"),
        allowed_transponder_bandwidths_mhz=(36, 72),
        coverage_hint="Turkey, East, West",
        public_note="50E GEO communications satellite with first C-band use in the Turksat fleet.",
        aliases=("Türksat 4B",),
    ),
    "turksat-5a": SatelliteProfile(
        profile_id="turksat-5a",
        satellite_name="Turksat 5A",
        mission_domain="communications",
        operator="Turksat",
        launch_year=2021,
        orbit_type="GEO",
        orbital_slot_deg_e=31.0,
        allowed_channels=("satcom-relay", "broadcast", "telemetry"),
        allowed_uplink_bands=("Ku-Band", "New Ku-Band"),
        allowed_downlink_bands=("Ku-Band", "New Ku-Band"),
        allowed_protocols=("transponder-metadata", "broadcast-monitor"),
        allowed_transponder_bandwidths_mhz=(36, 72),
        coverage_hint="Turkey, East, West, MENA, South Africa, West Africa",
        public_note="31E GEO communications satellite for Ku and New Ku coverage.",
        aliases=("Türksat 5A",),
    ),
    "turksat-5b": SatelliteProfile(
        profile_id="turksat-5b",
        satellite_name="Turksat 5B",
        mission_domain="communications",
        operator="Turksat",
        launch_year=2021,
        orbit_type="GEO",
        orbital_slot_deg_e=42.0,
        allowed_channels=("satcom-relay", "broadband", "telemetry"),
        allowed_uplink_bands=("Ku-Band", "New Ku-Band", "Ka-Band", "Ka-BSS Band"),
        allowed_downlink_bands=("Ku-Band", "New Ku-Band", "Ka-Band", "Ka-BSS Band"),
        allowed_protocols=("transponder-metadata", "hts-monitor"),
        coverage_hint="Turkey, West, Middle East, Ka spot beams",
        public_note="42E GEO HTS-class communications satellite with over 50 Gbps Ka-band capacity.",
        aliases=("Türksat 5B",),
    ),
    "turksat-6a": SatelliteProfile(
        profile_id="turksat-6a",
        satellite_name="Turksat 6A",
        mission_domain="communications",
        operator="Turksat",
        launch_year=2024,
        orbit_type="GEO",
        orbital_slot_deg_e=42.0,
        altitude_km=35786.0,
        allowed_channels=("satcom-relay", "broadcast", "telemetry"),
        allowed_uplink_bands=("Ku-Band", "Ku-BSS Band", "Ka-Band", "Q/V-Band"),
        allowed_downlink_bands=("Ku-Band", "Ku-BSS Band", "Ka-Band", "Q/V-Band"),
        allowed_protocols=("transponder-metadata", "broadcast-monitor"),
        coverage_hint="Turkey, East, West",
        public_note="First indigenous Turkish communications satellite in GEO at 42E.",
        aliases=("Türksat 6A",),
    ),
    "gokturk-1": SatelliteProfile(
        profile_id="gokturk-1",
        satellite_name="Gokturk-1",
        mission_domain="earth_observation",
        operator="Turkish Space Agency / Ministry of National Defense",
        launch_year=2016,
        orbit_type="LEO",
        allowed_channels=("eo-downlink", "imagery-metadata", "tasking"),
        allowed_downlink_bands=("X-Band",),
        allowed_tmtc_bands=("S-Band",),
        allowed_protocols=("eo-metadata", "tasking-manifest"),
        sensor_type="optical",
        resolution_hint="high-resolution optical",
        coverage_hint="Optical remote sensing",
        public_note="High-resolution optical remote-sensing satellite.",
        aliases=("GÖKTÜRK-1",),
    ),
    "gokturk-2": SatelliteProfile(
        profile_id="gokturk-2",
        satellite_name="Gokturk-2",
        mission_domain="earth_observation",
        operator="Turkish Space Agency / Ministry of National Defense",
        launch_year=2012,
        orbit_type="LEO",
        allowed_channels=("eo-downlink", "imagery-metadata", "tasking"),
        allowed_downlink_bands=("X-Band",),
        allowed_tmtc_bands=("S-Band",),
        allowed_protocols=("ccsds-tm", "eo-metadata", "tasking-manifest"),
        sensor_type="optical",
        resolution_hint="high-resolution optical",
        coverage_hint="Remote sensing",
        public_note="Indigenously developed high-resolution remote-sensing satellite.",
        aliases=("GÖKTÜRK-2",),
    ),
    "imece": SatelliteProfile(
        profile_id="imece",
        satellite_name="IMECE",
        mission_domain="earth_observation",
        operator="TUBITAK Space / Turkish Space Agency",
        launch_year=2023,
        orbit_type="LEO_SSO",
        altitude_km=680.0,
        allowed_channels=("eo-downlink", "imagery-metadata", "tasking"),
        allowed_downlink_bands=("X-Band",),
        allowed_tmtc_bands=("S-Band",),
        allowed_protocols=("ccsds-tm", "eo-metadata", "tasking-manifest"),
        sensor_type="electro_optical",
        resolution_hint="sub-meter electro-optical",
        coverage_hint="Global earth observation",
        public_note="Sub-meter EO mission with public X-band CCSDS high-rate downlink and S-band TM/TC.",
        aliases=("İMECE", "IMECE", "GOKTURK-2B"),
    ),
}


def get_satellite_profile(profile_id: str | None) -> SatelliteProfile:
    if not profile_id:
        return SATELLITE_PROFILES["generic-bkzs"]
    return SATELLITE_PROFILES.get(profile_id, SATELLITE_PROFILES["generic-bkzs"])


def satellite_profile_options() -> list[tuple[str, str]]:
    return [(profile.profile_id, profile.display_name) for profile in SATELLITE_PROFILES.values()]


def build_satellite_payload(profile_id: str | None) -> dict[str, object]:
    profile = get_satellite_profile(profile_id)
    if profile.profile_id == "generic-bkzs":
        return {}
    payload: dict[str, object] = {
        "satellite_profile_id": profile.profile_id,
        "satellite_id": profile.satellite_name,
        "satellite_class": profile.mission_domain,
        "orbit_type": profile.orbit_type,
        "protocol_family": profile.allowed_protocols[0] if profile.allowed_protocols else "normalized-metadata",
    }
    if profile.orbital_slot_deg_e is not None:
        payload["orbital_slot_deg_e"] = profile.orbital_slot_deg_e
    if profile.altitude_km is not None:
        payload["altitude_km"] = profile.altitude_km
    if profile.allowed_uplink_bands:
        payload["uplink_band"] = profile.allowed_uplink_bands[0]
    if profile.allowed_downlink_bands:
        payload["downlink_band"] = profile.allowed_downlink_bands[0]
    if profile.allowed_tmtc_bands:
        payload["tmtc_band"] = profile.allowed_tmtc_bands[0]
    if profile.allowed_transponder_bandwidths_mhz:
        payload["transponder_bandwidth_mhz"] = profile.allowed_transponder_bandwidths_mhz[0]
    if profile.sensor_type:
        payload["sensor_type"] = profile.sensor_type
    if profile.resolution_hint:
        payload["resolution_hint"] = profile.resolution_hint
    return payload
