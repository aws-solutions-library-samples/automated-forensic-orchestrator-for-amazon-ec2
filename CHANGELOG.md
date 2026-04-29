# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.2] - 2026-04-28

### Changed

- Replaced deprecated CDK APIs: `VpcProps.cidr` → `ipAddresses`, `TableOptions.pointInTimeRecovery` → `pointInTimeRecoverySpecification`, `StateMachineProps.definition` → `definitionBody`
- Bumped `aws-cdk` 2.1019.1 → 2.1119.0, `aws-cdk-lib` 2.202.0 → 2.251.0, `cdk-nag` 2.26.19 → 2.38.2, `constructs` → 10.6.0
- Bumped all `@aws-sdk/client-*` packages to 3.1038.0 (resolves Dependabot PR #35 transitive `@smithy/config-resolver`)
- Bumped `@babel/core` 7.26.10 → 7.29.0, `ts-jest` 29.1.0 → 29.4.9, `ts-node` 10.8.2 → 10.9.2, `eslint-config-prettier` → 8.10.2
- Bumped Python `requests` to 2.32.4 and `certifi` to 2024.7.4 (resolves Dependabot PRs #29, #31, #33)
- Untracked `source/cdk.context.json` (per `.gitignore`); lookups now regenerate per environment

## [1.3.1] - 2025-07-18

### Changed

- Added test coverage for EKS cluster automation

## [1.3.0] - 2025-07-07

### Changed

- Added support for EKS clusters hosted on EC2

## [1.2.5] - 2025-06-20

### Changed

- Updated dependencies to address CVE-2025-27789

## [1.2.4] - 2024-11-26

### Changed

- Updated dependencies to address cross-spawn CVE-2024-21538

## [1.2.3] - 2024-06-09

### Changed

- Updated dependencies to address CVE-2020-22083, CVE-2020-22083, CVE-2022-42969, CVE-2024-34064, CVE-2024-35195, CVE-2024-37891, CVE-2024-4068  

## [1.2.2] - 2024-05-01

### Changed

- Removed the metric collector module
- Updated dependencies

## [1.2.1] - 2023-07-04

### Fixed

- Mitigated impact caused by new default settings for S3 Object Ownership (ACLs disabled) for all new S3 buckets.

## [1.2.0] - 2023-05-06

### Changed

- Red hat linux support, version 8.5
- Windows memory capture support for windows server 2016 and server 2019
- Update new profile building step functions
- Bug fixes for existing san sift images
- Improved logging 
- Improved customization for user defined ssm document.

## [1.1.0] - 2022-11-22

### Changed

- Invalid existing sts session credential after isolation
- Detach EIP from compromised instances
- Attempt isolation regardless memory acquisition result
- Instance isolation - profiles update
- Add EBS termination protection
- Enable termination protection for ec2 instance

## [1.0.0] - 2022-06-20

### Added

-   All files, initial version
