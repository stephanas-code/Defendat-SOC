#!/bin/bash

echo "Testing artifact data replay..."
echo "This will replay the Global_Cybersecurity_Threats_2015-2024.csv data to the dashboard"
echo ""

# Check if backend is running
if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "ERROR: Backend is not running at http://localhost:8000"
    echo "Please start the backend first using: docker-compose up backend"
    exit 1
fi

echo "Backend is running. Starting data replay..."
echo ""

python scripts/replay_global_threats_csv.py --csv artifacts/Global_Cybersecurity_Threats_2015-2024.csv --backend http://localhost:8000 --rate 5

if [ $? -eq 0 ]; then
    echo ""
    echo "SUCCESS: Data replay completed. Check the dashboard at http://localhost:3000"
else
    echo ""
    echo "ERROR: Data replay failed. Check the error messages above."
    exit 1
fi
