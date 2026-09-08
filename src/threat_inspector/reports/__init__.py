"""
Report generators for Threat Inspector.
"""

from threat_inspector.reports.html import generate_html_report

# The formats `ThreatInspector.generate_report` can actually produce.
#
# This exists because "pdf" was advertised in three places and implemented in
# none: the CLI offered it as a --format choice, the API mapped a media type for
# it, and the docstring listed it — while generate_report has no pdf branch at
# all. The CLI printed a failure and still exited 0; the API returned 500.
# Advertising an output that cannot be produced is worse than not offering it.
REPORT_FORMATS = ("html", "json", "csv")

__all__ = ["REPORT_FORMATS", "generate_html_report"]
