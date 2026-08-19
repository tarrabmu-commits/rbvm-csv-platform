# EPSS Next Increment

After `EPSS_CSV_V1` passes CI, the next isolated change should add PostgreSQL EPSS
history/current views and the transactional importer. It must retain score date,
observation time, model version, source, and source-byte SHA-256, and must not create
a direct FIRST-to-database path.
