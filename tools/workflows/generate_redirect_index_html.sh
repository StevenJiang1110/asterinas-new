#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

# This script is used to generated redirecting index.html for API documentation website.

set -e

print_help() {
    echo "Usage: $0 url [output]"
    echo "url:      The URL to which index.html will be directed."
    echo "output:   The path to the generated HTML file. Default is index.html in the current directory."
}

if [ "$#" -eq 0 ]; then
  echo "Error: At least one parameter is required."
  print_help
  exit 1
fi

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  print_help
  exit 0
fi

URL=$1
OUTPUT=${2:-index.html}

TEMPLATE="
<!DOCTYPE html>\n
<html>\n
<head>\n
  <meta http-equiv=\"refresh\" content=\"0; URL=${URL}\">\n
</head>\n
<body>\n
  <p>Redirecting to a new page...</p>\n
  <script>\n
    // If the browser doesn't support automatic redirection, display a link for manual redirection\n
    window.location.href = \"${URL}\";\n
  </script>\n
</body>\n
</html>\n
"

echo -e ${TEMPLATE} > ${OUTPUT}


