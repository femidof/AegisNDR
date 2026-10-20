FROM jasonish/suricata:7.0.10
USER root
# Vendor defaults are public configuration. Capture runs with NET_RAW alone;
# it must not need DAC_READ_SEARCH to read files owned by the image's account.
RUN chmod a+r /etc/suricata/suricata.yaml /etc/suricata/classification.config /etc/suricata/reference.config /etc/suricata/threshold.config
