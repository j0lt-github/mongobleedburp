# MongoBleed Burp Extension

Burp Suite extension to detect CVE-2025-14847 (MongoBleed) via manual leak tests from a dedicated UI tab.

Repository: https://github.com/j0lt-github/mongobleedburp
Current version: **1.1.0**

## Features

- **Manual test UI tab** with host/port and min/max offsets
- **Temporary-file leak capture** for large output handling
- **Hex + ASCII** and **text views** for leak inspection
- **Keyword highlighting** for common secret patterns
- **Download Output** button to export results as `.txt`

Creator: **j0lt**

## Requirements

- Burp Suite (Professional or Community)
- JDK 8+

## Build

1. Build the JAR (Gradle will fetch the Burp API from Maven Central):

```bash
gradle jar
```

The output JAR is in `build/libs/mongobleed-burp-<version>.jar` (for this release: `mongobleed-burp-1.1.0.jar`).

## Load in Burp

1. Burp → Extensions → Add
2. Type: Java
3. Select `build/libs/mongobleed-burp-1.1.0.jar`

## Usage

### Manual Test 

- Set **Host**, **Port**, and offset range
- Click **Run Scan**
- Review leaks in the **Results** table and **Hex/Text** views
- Use **Download Output** to save a `.txt` report anywhere you choose

Output lifecycle:
- Scan output is written to a temporary file (not kept in heap memory)
- A new scan rotates to a new temp file and removes the previous one
- Unload/reload or Burp shutdown removes temp output files

## Disclaimer

For authorized security testing only.
