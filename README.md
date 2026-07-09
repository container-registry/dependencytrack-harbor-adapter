# mikebom-harbor-adapter

A Harbor scanner adapter that generates Software Bill of Materials (SBOM) documents for container images using [mikebom](../mikebom). It implements the Harbor scanner adapter API so Harbor can invoke it as a pluggable scanner, but it produces SBOMs only and has no vulnerability scanning or reporting capability.
