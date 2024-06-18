# 3rd Party Dependency Vulnerabilities

This document tracks vulnerabilities in 3rd party dependencies that directly affect the standard release product of libmongocrypt.

> [!IMPORTANT]
> The "standard release product" is defined as the set of files which are _installed_ by a configuration, build, and install of libmongocrypt. This includes static/shared library files, header files, and packaging files for supported build configurations. Vulnerabilities for 3rd party dependencies that are bundled with the standard release product are reported in this document.
>
> Language bindings (in the `bindings` directory), test files, utility scripts, documentation generators, and other miscellaneous files and artifacts are NOT considered part of the standard release product, even if they are included in the release distribution tarball. Vulnerabilities for such 3rd party dependencies are NOT reported in this document.

## Template

This section provides a template that may be used for actual vulnerability reports further below.

### CVE-YYYY-NNNNNN

- **Date Detected:** YYYY-MM-DD
- **Severity:** Low, Medium, High, or Critical
- **Detector:** Silk or Snyk
- **Description:** A short vulnerability description.
- **Dependency:** Name and version of the 3rd party dependency.
- **Upstream Status:** False Positive, Won't Fix, Fix Pending, or Fix Available. This is the fix status for the 3rd party dependency, not libmongocrypt. "Fix Available" should include the version and/or date when the fix was released, e.g. "Fix Available (1.2.3, 1970-01-01)".
- **Fix Status:** False Positive, Won't Fix, Fix Pending, or Fix Committed. This is the fix status for the libmongocrypt. "False Positive" and "Won't Fix" must include rationale in notes below.
- **For Release:** The libmongocrypt release version for which the "Fix Status" above was last updated.
- **Notes:** Context or rationale for remediation, references to relevant issue trackers, etc.

## libbson

### CVE-2023-0437

- **Date Detected:** 2024-05-20
- **Severity:** Medium
- **Detector:** Snyk
- **Description:** Loop with Unreachable Exit Condition ('Infinite Loop')
- **Dependency:** mongodb/mongo-c-driver@1.17.7
- **Upstream Status:** Fix Available (1.25.0, 2023-11-01).
- **Fix Status:** Fix Committed.
- **For Release:** 1.10.1
- **Notes:** Fixed in libbson 1.25.0 ([CDRIVER-4747](https://jira.mongodb.org/browse/CDRIVER-4747)). Fixed in libmongocrypt by upgrading libbson to 1.27.1 ([MONGOCRYPT-685](https://jira.mongodb.org/browse/MONGOCRYPT-685)).

## IntelDFP

None.
