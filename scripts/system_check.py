#!/usr/bin/env python3
"""System health check script for AI Anomaly IDS.

This script verifies all components are operational and ready for production deployment.
"""

import sys
import json
import urllib.request
import urllib.error
from datetime import datetime


def check_backend_health(backend_url="http://localhost:8000"):
    """Check if backend is running and healthy."""
    try:
        health_url = f"{backend_url}/health"
        with urllib.request.urlopen(health_url, timeout=5) as response:
            data = json.loads(response.read().decode())
            return True, data
    except Exception as e:
        return False, {"error": str(e)}


def check_backend_status(backend_url="http://localhost:8000"):
    """Check detailed backend status."""
    try:
        status_url = f"{backend_url}/status"
        with urllib.request.urlopen(status_url, timeout=5) as response:
            data = json.loads(response.read().decode())
            return True, data
    except Exception as e:
        return False, {"error": str(e)}


def check_alerts_endpoint(backend_url="http://localhost:8000"):
    """Check if alerts endpoint is working."""
    try:
        alerts_url = f"{backend_url}/alerts?limit=1"
        with urllib.request.urlopen(alerts_url, timeout=5) as response:
            data = json.loads(response.read().decode())
            return True, data
    except Exception as e:
        return False, {"error": str(e)}


def print_section(title):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_component_status(name, status, details=None):
    """Print component status with color coding."""
    status_symbol = "✓" if status else "✗"
    status_text = "OK" if status else "FAILED"
    
    print(f"{status_symbol} {name}: {status_text}")
    if details and not status:
        print(f"  Error: {details}")


def main():
    backend_url = "http://localhost:8000"
    
    print_section("AI Anomaly IDS - System Health Check")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Backend URL: {backend_url}")
    
    # Check basic health
    print_section("1. Backend Health Check")
    health_ok, health_data = check_backend_health(backend_url)
    print_component_status("Backend Service", health_ok, health_data.get("error") if not health_ok else None)
    
    if health_ok:
        print(f"  Models loaded:")
        for model, loaded in health_data.get("models", {}).items():
            status = "✓" if loaded else "✗"
            print(f"    {status} {model}: {'loaded' if loaded else 'not loaded'}")
    
    # Check detailed status
    print_section("2. Component Status")
    status_ok, status_data = check_backend_status(backend_url)
    print_component_status("Status Endpoint", status_ok, status_data.get("error") if not status_ok else None)
    
    if status_ok:
        components = status_data.get("components", {})
        print_component_status("Database", components.get("database", {}).get("ok", False))
        print_component_status("Redis", components.get("redis", {}).get("ok", False))
        print_component_status("Kafka", components.get("kafka", {}).get("ok", False))
        
        overall_ok = status_data.get("ok", False)
        print(f"\n  Overall System Status: {'OPERATIONAL' if overall_ok else 'DEGRADED'}")
    
    # Check alerts endpoint
    print_section("3. Alerts System")
    alerts_ok, alerts_data = check_alerts_endpoint(backend_url)
    print_component_status("Alerts Endpoint", alerts_ok, alerts_data.get("error") if not alerts_ok else None)
    
    if status_ok:
        alerts_stats = status_data.get("alerts", {})
        print(f"  Total Alerts: {alerts_stats.get('total', 0)}")
        print(f"  Last Hour: {alerts_stats.get('last_1h', 0)}")
        print(f"  Last 24h: {alerts_stats.get('last_24h', 0)}")
        print(f"  Critical Total: {alerts_stats.get('critical_total', 0)}")
    
    # Production readiness assessment
    print_section("4. Production Readiness Assessment")
    
    models_loaded = health_ok and any(health_data.get("models", {}).values())
    components_ok = status_ok and status_data.get("ok", False)
    alerts_working = alerts_ok
    
    issues = []
    
    if not models_loaded:
        issues.append("ML models not loaded - run training scripts")
    if not components_ok:
        issues.append("Some components are not operational")
    if not alerts_working:
        issues.append("Alerts system not responding")
    
    if not issues:
        print("✓ System is PRODUCTION READY")
        print("\nNext steps:")
        print("  1. Test with replay scripts: python scripts/replay_network_flows.py")
        print("  2. Monitor dashboard at http://localhost:3000")
        print("  3. Consider enabling network capture for live monitoring")
    else:
        print("✗ System is NOT production ready")
        print("\nIssues to fix:")
        for issue in issues:
            print(f"  - {issue}")
        print("\nSee DEPLOYMENT.md for detailed instructions")
    
    print_section("Health Check Complete")
    
    # Return exit code based on readiness
    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
