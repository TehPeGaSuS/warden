# Find all the *.cpp files within the current source directory, and sort the list
file(GLOB TOOLS_SRCS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.cpp")
list(SORT TOOLS_SRCS)

# Iterate through all the source files
foreach(SRC ${TOOLS_SRCS})
  # Convert the source file extension to have no extension
  string(REGEX REPLACE "\\.cpp$" "" EXE ${SRC})
  # Only continue if this file isn't skipped
  if(NOT SKIP)
    # Generate the executable and set its linker flags, also set it to depend on the main Warden executable to be built beforehand
    add_executable(${EXE} ${SRC})
    add_dependencies(${EXE} ${PROGRAM_NAME})
    # Set the executable to be installed to the bin directory under the main directory
    install(TARGETS ${EXE}
      DESTINATION ${BIN_DIR}
      RUNTIME
    )
  endif()
endforeach()

# Install the mkpasswd script
install(
  PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/warden-mkpasswd
  DESTINATION ${BIN_DIR}
)

# If not on Windows, generate warden.service and wardenrc
if(NOT WIN32)
  if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    configure_file(
      ${Warden_SOURCE_DIR}/src/tools/warden.service.in
      ${Warden_BINARY_DIR}/src/tools/warden.service
    )
    install(
      PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/warden.service
      DESTINATION ${BIN_DIR}
    )
  endif()

  configure_file(
    ${Warden_SOURCE_DIR}/src/tools/wardenrc.in
    ${Warden_BINARY_DIR}/src/tools/wardenrc
  )
  install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/wardenrc
    DESTINATION ${BIN_DIR}
  )
endif()

# On non-Windows platforms, if RUNGROUP is set, change the permissions of the tools directory
if(NOT WIN32 AND RUNGROUP)
  install(CODE "execute_process(COMMAND ${CHMOD} 2770 \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/bin\")")
endif()
