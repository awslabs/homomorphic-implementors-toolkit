# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

message(STATUS "Searching Microsoft SEAL.")

# SEAL is a `git subtree` of this repository because some tweaks are made based on our needs.
# The subtree is under ${HIT_THIRD_PARTY_DIR}/seal/src
# These tweaks may be contributed back to SEAL git repo by opening issues.
# https://github.github.com/training-kit/downloads/submodule-vs-subtree-cheat-sheet/
add_subdirectory(${HIT_THIRD_PARTY_DIR}/seal/src)
