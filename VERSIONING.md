# Versioning Policy

The Homomorphic Implementors Toolkit (HIT) follows [semantic versioning][link-semver] standards.

Since HIT currently has two different branches (based on Lattigo and SEAL), we will maintain two parallel sets of releases.
Each version will correspond to a tag of the form `v${VERSION}-${BACKEND}`.
For example, the `0.1.2` release for SEAL will have the tag `v0.1.2-seal` while the `0.2.1` release for Lattigo will have the tag `v0.2.1-lattigo`.
Prior to `1.0.0` maintaining version equivalence between the two branch is *best effort only*.
(After `1.0.0` we will formalize our promises and versioning.)

## Major versions

Major version changes are significant and expected to break backwards compatibility.

## Minor versions

Minor version changes will not break compatibility between the previous minor versions;
to do so is a bug.
Encryption SDK changes will also involve addition of optional features, and non-breaking enhancements.
Additionally, any change to the version of a dependency is a minor version change.

## Patch versions

Patch versions changes are meant only for bug fixes,
and will not break compatibility of the current major version.
A patch release will contain a collection of minor bug fixes, 
or individual major and security bug fixes, depending on severity.

[link-semver]:https://semver.org/