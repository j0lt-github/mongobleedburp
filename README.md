# MongoBleed Burp Extension (j0lt)

Burp Suite extension to detect CVE-2025-14847 (MongoBleed) via manual leak tests from a dedicated UI tab.

Repository: https://github.com/j0lt-github/mongobleedburp

## Features

- **Manual test UI tab** with host/port and min/max offsets
- **In-memory leak capture** (no `.bin` written to disk)
- **Hex + ASCII** and **text views** for leak inspection
- **Keyword highlighting** for common secret patterns

Creator: **j0lt**

## Requirements

- Burp Suite (Professional or Community)
- JDK 8+

## Build

1. Build the JAR (Gradle will fetch the Burp API from Maven Central):

```bash
gradle jar
```

The output JAR is in `build/libs/mongobleed-burp.jar`.

## Load in Burp

1. Burp → Extensions → Add
2. Type: Java
3. Select `build/libs/mongobleed-burp.jar`

## Usage

### Manual Test 

- Set **Host**, **Port**, and offset range
- Click **Run Scan**
- Review leaks in the **Results** table and **Hex/Text** views

## Disclaimer

For authorized security testing only.
