#!/bin/bash

# Test runner script for SentinelRBAC
echo "Running SentinelRBAC tests..."
echo "================================"

# Run tests with verbose output
go test -v

echo ""
echo "================================"
echo "Running tests with coverage..."
go test -cover

echo ""
echo "================================"
echo "Running tests with detailed coverage..."
go test -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
echo "Coverage report generated: coverage.html"
echo "Note: Coverage files are not tracked in git (see .gitignore)"
