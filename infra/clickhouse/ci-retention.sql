-- The checksum-pinned PCAP has a fixed historical timestamp. Keep its rows
-- throughout CI; production keeps the normal retention policy.
ALTER TABLE hybrid_ndr.network_events
MODIFY TTL toDateTime(event_time) + toIntervalDay(3650) DELETE;
