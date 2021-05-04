if(NOT APPINITDISPATCHER_PATH)
    message(FATAL_ERROR "You need -DAPPINITDISPATCHER_PATH=...")
endif()

get_filename_component(APPINITDISPATCHER_DIR "${APPINITDISPATCHER_PATH}" DIRECTORY)
file(TO_NATIVE_PATH "${APPINITDISPATCHER_PATH}" APPINITDISPATCHER_PATH)

set(INSTALL_REG "${APPINITDISPATCHER_DIR}/register_AppInitDLL.reg")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    configure_file("${CMAKE_CURRENT_LIST_DIR}/register_x64.reg.in" "${INSTALL_REG}")
else()
    configure_file("${CMAKE_CURRENT_LIST_DIR}/register_x86.reg.in" "${INSTALL_REG}")
endif()
file(TO_NATIVE_PATH "${INSTALL_REG}" INSTALL_REG)

if(NOT EXISTS "${APPINITDISPATCHER_DIR}/AppInitHook.ini")
    message(STATUS "Creating AppInitHook.ini...")
    file(
        COPY "${CMAKE_CURRENT_LIST_DIR}/AppInitHook.ini"
        DESTINATION "${APPINITDISPATCHER_DIR}"
    )
endif()

message(STATUS "Importing ${INSTALL_REG} into the registry...")
execute_process(COMMAND cmd /C start "${INSTALL_REG}")
