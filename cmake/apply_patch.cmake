# Idempotently apply a patch to a fetched dependency source tree — used as a
# FetchContent PATCH_COMMAND. FetchContent runs PATCH once per populate, but the
# reverse --check guard makes a re-run a safe no-op, so a stale build dir or a
# manual re-configure can't fail with "already applied". Generic over the dep
# (pass LABEL for the status messages).
#
# Args (via -D): GIT_EXECUTABLE, PATCH_FILE, SRC_DIR, LABEL
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
  message(STATUS "${LABEL}: patch already applied")
  return()
endif()

execute_process(
  COMMAND "${GIT_EXECUTABLE}" apply "${PATCH_FILE}"
  WORKING_DIRECTORY "${SRC_DIR}"
  RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "${LABEL}: failed to apply ${PATCH_FILE}")
endif()
message(STATUS "${LABEL}: applied ${PATCH_FILE}")
