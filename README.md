# ICSNPP-xxx

Industrial Control Systems Network Protocol Parsers (ICSNPP) - xxx

## How to use this template

- resolve `xxx`
- add the logging capabilities
- if necessary the manual install instructions
- resolve all ** marked texts.

## Overview

*short description where and for what the protocol is used in general.*

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
zkg refresh
zkg install icsnpp-xxx
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly, users will see `ANALYZER_SPICY_xxx` under the list of `Zeek::Spicy` analyzers.

If users have ZKG configured to load packages (see `@load packages` in the( [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and these scripts will automatically be loaded and ready to go.)

### Manual Install

*optional if necessary.
If users are compiling the code manually, use clang as the compiler by compiling zeek with clang. Installing the package with zkg is not impacted.*

## Logging Capabilities

[see examples]( https://github.com/cisagov/ICSNPP)

## License

The software was developed on behalf of the BSI (Federal Office for Information Security)

Copyright (c) XXX by DINA-Community XXX License. [See License](/LICENSE)

*add license file in main folder.*
