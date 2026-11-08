# Architecture readability update

Includes the previous S4BLE 3.4 product update.

- Connections use rounded right-angle routes in the gaps between cards, avoiding resource-card interiors.
- Wider resource spacing and shared port allocation separate incoming and outgoing arrows.
- Category overview combines reciprocal relationships into one two-headed connection, preserving evidence direction and counts. The previous nine-connection cap is removed.
- Trace resource is the default: dense maps (over 24 relationships) invite selection of a resource. Selecting a resource displays its direct links. All connections restores the full map. Displayed and total counts are always shown.
- Path and blast-radius focus remain supported. Evidence drawers and confidence filters remain available.
- Arrows describe imported dependencies, not verified live traffic. If an unusual layout cannot be routed safely, the resource-map status reports omitted routes; evidence is retained.

Validation: all 51 automated tests pass, including dense multi-column, reverse-direction and category routing checks. Browser-tested a 20-resource Terraform example with 54 total relationships: the compute context contains 53, all 53 render in All connections, and selecting app_00 traces its three direct relationships.

The analysis engine, import logic, product pages, dependencies, and startup commands are unchanged. See START_HERE.md for setup.
