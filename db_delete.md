# Backup the Database to a file
sudo docker compose exec timescaledb pg_dump -U ids ids > backup.sql


# Empty (Truncate) the Tables
sudo docker compose exec timescaledb psql -U ids -d ids -c "TRUNCATE TABLE alerts, flows CASCADE;"
