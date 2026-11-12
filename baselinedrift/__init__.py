"""Windows Server security baseline drift review: are our Windows servers still configured the way the approved security baseline
says, which ones have drifted since the last review, why (a GPO not applying, a local change, an exception that expired), and what do
we fix first? From the baseline, the server inventory, the collected settings, last month's collection, the exceptions and the Group
Policy results: compliance per server, area, tier and site, high-risk deviations, new drift, root-cause hints, exceptions to review,
hygiene (servers not reporting, uptime, patch age) and a one-page pack for the monthly security and infrastructure review."""
__version__ = "1.0.0"
