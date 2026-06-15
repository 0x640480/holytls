# Idempotently apply a patch to the fetched BoringSSL source tree. Used as the
# boringssl PATCH_COMMAND (fork build only). FetchContent normally runs PATCH
# once per populate, but a reverse --check guard makes a re-run a safe no-op so a
# stale build dir or a manual re-configure can't fail with "already applied".
#
# Args (via -D): GIT_EXECUTABLE, PATCH_FILE, SRC_DIR
if(NOT GIT_EXECUTABLE)
  find_package(Git QUIET REQUIRED)
endif()

# git apply works on a plain file tree (no repo required). If the patch already
# applies in reverse, it is already present -> nothing to do.
execute_process(
  COMMAND "${GIT_EXECUTABLE}" apply --reverse --check "${PATCH_FILE}"
  WORKING_DIRECTORY "${SRC_DIR}"
  RESULT_VARIABLE already_applied
  OUTPUT_QUIET ERROR_QUIET)
if(already_applied EQUAL 0)
  message(STATUS "boringssl: Firefox TLS1.3 legacy-ext patch already applied")
  return()
endif()

execute_process(
  COMMAND "${GIT_EXECUTABLE}" apply "${PATCH_FILE}"
  WORKING_DIRECTORY "${SRC_DIR}"
  RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "boringssl: failed to apply ${PATCH_FILE}")
endif()
message(STATUS "boringssl: applied Firefox TLS1.3 legacy-ext patch")
