"""
MDS Provider API client implementation.
"""

import datetime
import time

from ..encoding import TimestampEncoder, TimestampDecoder
from ..files import ConfigFile
from ..providers import Provider
from ..schemas import STATUS_CHANGES, TRIPS, EVENTS, VEHICLES, Schema
# also support a few newer APIs
from ..schemas import STOPS
# also support a few Agency APIs
from ..schemas import POLICIES, GEOGRAPHIES
from ..versions import Version
from .auth import auth_types


class Client():
    """
    Client for MDS Provider APIs.
    """

    def __init__(self, provider=None, config={}, **kwargs):
        """
        Parameters:
            provider: str, UUID, Provider, optional
                Provider instance or identifier that this client queries by default.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            version: str, Version, optional
                The MDS version to target. By default, use Version.mds_lower().

        Extra keyword arguments are taken as config attributes for the Provider.
        """
        if isinstance(config, ConfigFile):
            config = config.dump()

        # look for version first in config, then kwargs, then use default
        self.version = Version(config.pop("version", kwargs.pop("version", Version.mds_lower())))
        self.version.raise_if_unsupported()

        # merge config with the rest of kwargs
        self.config = { **config, **kwargs }

        self.provider = None
        if provider:
            self.provider = Provider(provider, ref=self.version, **self.config)

    def __repr__(self):
        data = [str(self.version)]
        if self.provider:
            data.append(self.provider.provider_name)
        data = "'" + "', '".join(data) + "'"
        return f"<mds.api.Client ({data})>"

    def _media_type_version_header(self, version):
        """
        The custom MDS media-type and version header, using this client's version.
        Must use a different header (as per different specs of different MDS versions:
          before version 1.0
            https://github.com/openmobilityfoundation/mobility-data-specification/blob/0.3.x/provider/README.md
              => application/vnd.mds.provider+json
          starting from version 1.0
            https://github.com/openmobilityfoundation/mobility-data-specification/blob/release-1.0.0/general-information.md#versioning
              => application/vnd.mds+json;version            
        """
        if version.tuple[0] < 1:
            return "Accept", f"application/vnd.mds.provider+json;version={version.header}"
        return "Accept", f"application/vnd.mds+json;version={version.header}"

    def _provider_or_raise(self, provider, **kwargs):
        """
        Get a Provider instance from the argument, self, or raise an error.
        """
        provider = provider or self.provider

        if provider is None:
            raise ValueError("Provider instance not found for this Client.")

        return Provider(provider, **kwargs)

    def get(self, record_type, provider=None, **kwargs):
        """
        Request Provider data, returning a list of non-empty payloads.

        Parameters:
            record_type: str
                The type of MDS Provider record.

            provider: str, UUID, Provider, optional
                Provider instance or identifier to issue this request to.
                By default issue the request to this client's Provider instance.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            end_time: datetime, int, optional
                When version < 0.4.0 and requesting status_changes, filters for events occurring before the given time.
                When version >= 0.4.0 and requesting trips, filters for trips ending within the hour of the given
                timestamp. Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            event_time: datetime, int, optional
                When version >= 0.4.0 and requesting status_changes, filters for events occurring within the hour of
                the given timestamp. Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            max_end_time: datetime, int, optional
                When version < 0.4.0 and requesting trips, filters for trips where end_time occurs before the given
                time. Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            min_end_time: datetime, int, optional
                when version < 0.4.0 and requesting trips, filters for trips where end_time occurs at or after the
                given time. Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            paging: bool, optional
                When version < 0.4.0, True (default) to follow paging and request all available data.
                False to request only the first page.
                Unsupported for version >= 0.4.0.

            start_time: datetime, int, optional
                When version < 0.4.0 and requesting status_changes, filters for events occuring at or after
                the given time. Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            rate_limit: int, optional
                Number of seconds of delay to insert between paging requests.

            version: str, Version, optional
                The MDS version to target.

            Additional keyword arguments are passed through as API request parameters.

        Return:
            list
                The non-empty payloads (e.g. payloads with data records), one for each requested page.
        """
        version = Version(kwargs.pop("version", self.version))
        version.raise_if_unsupported()

        if version < Version._040_():
            if record_type not in [STATUS_CHANGES, TRIPS]:
                raise ValueError(f"MDS Version {version} only supports {STATUS_CHANGES} and {TRIPS}.")
            # adjust time query formats
            if record_type == STATUS_CHANGES:
                kwargs["start_time"] = self._date_format(kwargs.pop("start_time", None), version, record_type)
                kwargs["end_time"] = self._date_format(kwargs.pop("end_time", None), version, record_type)
            elif record_type == TRIPS:
                kwargs["min_end_time"] = self._date_format(kwargs.pop("min_end_time", None), version, record_type)
                kwargs["max_end_time"] = self._date_format(kwargs.pop("max_end_time", None), version, record_type)
        elif version < Version._041_() and record_type == VEHICLES:
            raise ValueError(f"MDS Version {version} does not support the {VEHICLES} endpoint.")
        else:
            # parameter checks for record_type and version
            Client._params_check(record_type, version, **kwargs)
            # adjust query params
            if record_type == STATUS_CHANGES:
                kwargs["event_time"] = self._date_format(kwargs.pop("event_time"), version, record_type)
            elif record_type == TRIPS:
                kwargs["end_time"] = self._date_format(kwargs.pop("end_time"), version, record_type)
                # remove unsupported params
                kwargs.pop("device_id", None)
                kwargs.pop("vehicle_id", None)
            elif record_type == EVENTS:
                kwargs["start_time"] = self._date_format(kwargs.pop("start_time"), version, record_type)
                kwargs["end_time"] = self._date_format(kwargs.pop("end_time"), version, record_type)

        config = kwargs.pop("config", self.config)
        provider = self._provider_or_raise(provider, **config)
        rate_limit = int(kwargs.pop("rate_limit", 0))

        # paging is only supported for status_changes and trips prior to version 0.4.1
        paging_supported = any([
            (record_type in [STATUS_CHANGES, TRIPS] and version < Version._041_()),
            record_type not in [STATUS_CHANGES, TRIPS]
        ])
        paging = paging_supported and bool(kwargs.pop("paging", True))

        if not hasattr(provider, "headers"):
            setattr(provider, "headers", {})

        provider.headers.update(dict([(self._media_type_version_header(version))]))

        # request
        return self._request(provider, record_type, kwargs, paging, rate_limit)

    def get_status_changes(self, provider=None, **kwargs):
        """
        Request status changes, returning a list of non-empty payloads.

        Parameters:
            provider: str, UUID, Provider, optional
                Provider instance or identifier to issue this request to.
                By default issue the request to this client's Provider instance.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            start_time: datetime, int, optional
                When version < 0.4.0, filters for events occuring at or after the given time.
                Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            end_time: datetime, int, optional
                When version < 0.4.0, filters for events occurring before the given time.
                Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            event_time: datetime, int, optional
                When version >= 0.4.0, filters for events occurring within the hour of the given timestamp.
                Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            paging: bool, optional
                When version < 0.4.0, True (default) to follow paging and request all available data.
                False to request only the first page.
                Unsupported for version >= 0.4.0.

            rate_limit: int, optional
                Number of seconds of delay to insert between paging requests.

            version: str, Version, optional
                The MDS version to target.

            Additional keyword arguments are passed through as API request parameters.

        Return:
            list
                The non-empty payloads (e.g. payloads with data records), one for each requested page.
        """
        version = Version(kwargs.get("version", self.version))
        version.raise_if_unsupported()

        Client._params_check(STATUS_CHANGES, version, **kwargs)

        return self.get(STATUS_CHANGES, provider, **kwargs)

    def get_trips(self, provider=None, **kwargs):
        """
        Request trips, returning a list of non-empty payloads.

        Parameters:
            provider: str, UUID, Provider, optional
                Provider instance or identifier to issue this request to.
                By default issue the request to this client's Provider instance.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            device_id: str, UUID, optional
                When version < 0.4.0, filters for trips taken by the given device.
                Invalid for other use-cases.

            vehicle_id: str, optional
                When version < 0.4.0, filters for trips taken by the given vehicle.
                Invalid for other use-cases.

            end_time: datetime, int, optional
                When version >= 0.4.0, filters for trips ending within the hour of the given timestamp.
                Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            max_end_time: datetime, int, optional
                When version < 0.4.0, filters for trips where end_time occurs before the given time.
                Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            min_end_time: datetime, int, optional
                when version < 0.4.0, filters for trips where end_time occurs at or after the given time.
                Invalid for other use-cases.
                Should be a datetime or int UNIX milliseconds.

            paging: bool, optional
                When version < 0.4.0, True (default) to follow paging and request all available data.
                False to request only the first page.
                Unsupported for version >= 0.4.0,

            rate_limit: int, optional
                Number of seconds of delay to insert between paging requests.

            version: str, Version, optional
                The MDS version to target.

            Additional keyword arguments are passed through as API request parameters.

        Return:
            list
                The non-empty payloads (e.g. payloads with data records), one for each requested page.
        """
        version = Version(kwargs.get("version", self.version))
        version.raise_if_unsupported()

        Client._params_check(TRIPS, version, **kwargs)

        return self.get(TRIPS, provider, **kwargs)

    def get_events(self, provider=None, **kwargs):
        """
        Request events, returning a list of non-empty payloads.

        Parameters:
            provider: str, UUID, Provider, optional
                Provider instance or identifier to issue this request to.
                By default issue the request to this client's Provider instance.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            paging: bool, optional
                True (default) to follow paging and request all available data.
                False to request only the first page.

            rate_limit: int, optional
                Number of seconds of delay to insert between paging requests.

            version: str, Version, optional
                The MDS version to target.

            Additional keyword arguments are passed through as API request parameters.

        Return:
            list
                The non-empty payloads (e.g. payloads with data records), one for each requested page.
        """
        version = Version(kwargs.get("version", self.version))
        version.raise_if_unsupported()

        if version < Version._040_():
            raise ValueError(f"MDS Version {version} does not support the events endpoint.")

        Client._params_check(EVENTS, version, **kwargs)

        return self.get(EVENTS, provider, **kwargs)

    def get_vehicles(self, provider=None, **kwargs):
        """
        Request vehicles, returning a list of non-empty payloads.

        Parameters:
            provider: str, UUID, Provider, optional
                Provider instance or identifier to issue this request to.
                By default issue the request to this client's Provider instance.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            paging: bool, optional
                True (default) to follow paging and request all available data.
                False to request only the first page.

            rate_limit: int, optional
                Number of seconds of delay to insert between paging requests.

            version: str, Version, optional
                The MDS version to target.

            Additional keyword arguments are passed through as API request parameters.

        Return:
            list
                The non-empty payloads (e.g. payloads with data records), one for each requested page.
        """
        version = Version(kwargs.get("version", self.version))
        version.raise_if_unsupported()

        if version < Version._041_():
            raise ValueError(f"MDS Version {version} does not support the {VEHICLES} endpoint.")

        Client._params_check(VEHICLES, version, **kwargs)

        return self.get(VEHICLES, provider, **kwargs)

    def get_stops(self, provider=None, **kwargs):
        """
        Request stops, returning a list of non-empty payloads.

        Parameters:
            provider: str, UUID, Provider, optional
                Provider instance or identifier to issue this request to.
                By default issue the request to this client's Provider instance.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            paging: bool, optional
                True (default) to follow paging and request all available data.
                False to request only the first page.

            rate_limit: int, optional
                Number of seconds of delay to insert between paging requests.

            version: str, Version, optional
                The MDS version to target.

            Additional keyword arguments are passed through as API request parameters.

        Return:
            list
                The non-empty payloads (e.g. payloads with data records), one for each requested page.
        """
        version = Version(kwargs.get("version", self.version))
        version.raise_if_unsupported()

        if version < Version._041_():
            raise ValueError(f"MDS Version {version} does not support the {STOPS} endpoint.")

        Client._params_check(STOPS, version, **kwargs)

        return self.get(STOPS, provider, **kwargs)

    def get_policies(self, provider=None, **kwargs):
        """
        Request policies, returning a list of non-empty payloads.

        Parameters:
            provider: str, UUID, Provider, optional
                Provider instance or identifier to issue this request to.
                By default issue the request to this client's Provider instance.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            paging: bool, optional
                True (default) to follow paging and request all available data.
                False to request only the first page.

            rate_limit: int, optional
                Number of seconds of delay to insert between paging requests.

            version: str, Version, optional
                The MDS version to target.

            Additional keyword arguments are passed through as API request parameters.

        Return:
            list
                The non-empty payloads (e.g. payloads with data records), one for each requested page.
        """
        version = Version(kwargs.get("version", self.version))
        version.raise_if_unsupported()

        if version < Version._041_():
            raise ValueError(f"MDS Version {version} does not support the {POLICIES} endpoint.")

        Client._params_check(POLICIES, version, **kwargs)

        return self.get(POLICIES, provider, **kwargs)

    def get_geographies(self, provider=None, **kwargs):
        """
        Request geographies, returning a list of non-empty payloads.

        Parameters:
            provider: str, UUID, Provider, optional
                Provider instance or identifier to issue this request to.
                By default issue the request to this client's Provider instance.

            config: dict, ConfigFile, optional
                Attributes to merge with the Provider instance.

            paging: bool, optional
                True (default) to follow paging and request all available data.
                False to request only the first page.

            rate_limit: int, optional
                Number of seconds of delay to insert between paging requests.

            version: str, Version, optional
                The MDS version to target.

            Additional keyword arguments are passed through as API request parameters.

        Return:
            list
                The non-empty payloads (e.g. payloads with data records), one for each requested page.
        """
        version = Version(kwargs.get("version", self.version))
        version.raise_if_unsupported()

        if version < Version._041_():
            raise ValueError(f"MDS Version {version} does not support the {GEOGRAPHIES} endpoint.")

        Client._params_check(GEOGRAPHIES, version, **kwargs)

        return self.get(GEOGRAPHIES, provider, **kwargs)

    @staticmethod
    def _request(provider, record_type, params, paging, rate_limit):
        """
        Send one or more requests to a provider's endpoint.

        Returns a list of payloads, with length corresponding to the number of non-empty responses.
        """
        # establish an authenticated session
        session = Client._session(provider)
        url = provider.endpoints[record_type]
        results = []
        first = True

        while (first or paging) and url:
            # get the page of data
            if first:
                r = session.get(url, params=params)
                first = False
            else:
                r = session.get(url)
            # bail for non-200 status
            if r.status_code != 200:
                Client._describe(r)
                break
            # check payload for data
            # for vehicles, keep payload regardless as last_updated and ttl info may be useful
            payload = r.json()
            if record_type == VEHICLES or Client._has_data(payload, record_type):
                results.append(payload)
            # check for next page
            url = Client._next_url(payload)
            if url and rate_limit:
                time.sleep(rate_limit)

        return results

    @staticmethod
    def _session(provider):
        """
        Establish an authenticated session with the provider.

        The provider is checked against all immediate subclasses of AuthorizationToken (and that class itself)
        and the first supported implementation is used to establish the authenticated session.

        Raises a ValueError if no supported implementation can be found.
        """
        for auth_type in auth_types():
            if getattr(auth_type, "can_auth")(provider):
                return auth_type(provider).session

        raise ValueError(f"A supported auth type for {provider.provider_name} could not be found.")

    @staticmethod
    def _describe(res):
        """
        Prints details about the given response.
        """
        print(f"Requested {res.url}, Response Code: {res.status_code}")
        print("Response Headers:")
        for k,v in res.headers.items():
            print(f"{k}: {v}")

        if res.status_code != 200:
            print(res.text)

    @staticmethod
    def _has_data(page, record_type):
        """
        Checks if this page has a "data" property with a non-empty payload.
        """
        data = page["data"] if "data" in page else {"__payload__": []}
        data_key = Schema(record_type).data_key
        payload = data[data_key] if data_key in data else []
        # MDS v2.0 directly has "record_type" field without any "data" field
        if not payload:
          payload = page[data_key] if data_key in page else []          
        print(f"Got payload with {len(payload)} {record_type}")
        return len(payload) > 0

    @staticmethod
    def _next_url(page):
        """
        Gets the next URL or None from page.
        """
        return page["links"].get("next") if "links" in page else None

    @staticmethod
    def _date_format(dt, version, record_type):
        """
        Format datetimes for querystrings.
        """
        if dt is None:
            return None
        if not isinstance(dt, datetime.datetime):
            # convert to datetime using decoder
            dt = TimestampDecoder(version=version).decode(dt)

        if version >= Version._040_() and record_type in [STATUS_CHANGES, TRIPS]:
            encoder = TimestampEncoder(version=version, date_format="hours")
        else:
            encoder = TimestampEncoder(version=version, date_format="unix")

        return encoder.encode(dt)

    @staticmethod
    def _params_check(record_type, version, **kwargs):
        """
        Common checks for record_type query parameters.
        """
        if record_type == STATUS_CHANGES and version >= Version._040_() and "event_time" not in kwargs:
            raise TypeError("The 'event_time' query parameter is required for status_changes requests.")

        elif record_type == TRIPS and version >= Version._040_() and "end_time" not in kwargs:
            raise TypeError("The 'end_time' query parameter is required for trips requests.")

        elif record_type == EVENTS:
            if "start_time" not in kwargs and "end_time" not in kwargs:
                raise TypeError("The 'start_time' and 'end_time' query paramters are required for events requests.")

            two_weeks = Client._date_format(datetime.datetime.utcnow() - datetime.timedelta(days=14), version, EVENTS)
            start = Client._date_format(kwargs["start_time"], version, EVENTS)
            end = Client._date_format(kwargs["end_time"], version, EVENTS)

            # less than --> earlier in time
            if start < two_weeks or end < two_weeks:
                raise ValueError("The 'start_time' and 'end_time' query parameters must be within two weeks from now.")

        elif record_type == VEHICLES:
            # currently no vehicles specific param checks
            pass
