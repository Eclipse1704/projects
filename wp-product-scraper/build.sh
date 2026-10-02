#!/bin/sh
# Builds dist/product-scraper.zip: the file you upload in WordPress (Plugins -> Add New -> Upload Plugin).
cd "$(dirname "$0")"
rm -rf dist && mkdir -p dist/product-scraper
cp -r product-scraper.php uninstall.php includes assets dist/product-scraper/
(cd dist && zip -qr product-scraper.zip product-scraper && rm -rf product-scraper)
echo "dist/product-scraper.zip"
