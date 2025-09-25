#!/bin/bash

# Make all test scripts executable
# Run this script on Linux to set proper permissions

echo "🔧 Setting executable permissions for all test scripts..."

chmod +x *.sh

echo "✅ Permissions set for:"
ls -la *.sh | awk '{print "   " $1 " " $9}'

echo ""
echo "🚀 Test scripts are now ready to run!"
echo "📖 See README.md for detailed usage instructions"