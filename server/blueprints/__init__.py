"""HTTP routes, one blueprint per area. URLs carry no blueprint prefix."""
from blueprints import analysis, auth, clustering, history, monitoring, pcaps, privacy, scan

ALL_BLUEPRINTS = tuple(
    module.bp for module in (auth, pcaps, privacy, clustering, analysis, monitoring, scan, history)
)
