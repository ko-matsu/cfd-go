project(external_download NONE)

include(../cmake/EnableCcache.cmake)
include(../cmake/ConvertSrclistFunction.cmake)

# env check
if($ENV{CFD_CMAKE_GIT_SSH})
if($ENV{CFD_CMAKE_GIT_SSH} STREQUAL "1")
set(USE_GIT_SSH   ON)
else()
set(USE_GIT_SSH   OFF)
endif()
else()
set(USE_GIT_SSH   OFF)
endif()

if($ENV{CFD_CMAKE_GIT_SKIP_UPDATE})
if($ENV{CFD_CMAKE_GIT_SKIP_UPDATE} STREQUAL "1")
set(GIT_SKIP_UPDATE   ON)
else()
set(GIT_SKIP_UPDATE   OFF)
endif()
else()
set(GIT_SKIP_UPDATE   OFF)
endif()

# load file
set(EXTERNAL_LOCAL_FILENAME  local_resource/external_project_local_setting.config)
set(LOCAL_VERSION_FILE  ${CMAKE_SOURCE_DIR}/${EXTERNAL_LOCAL_FILENAME})
if(EXISTS ${LOCAL_VERSION_FILE})
transform_makefile_srclist(${LOCAL_VERSION_FILE} "${CMAKE_CURRENT_BINARY_DIR}/${EXTERNAL_LOCAL_FILENAME}.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/${EXTERNAL_LOCAL_FILENAME}.cmake)
endif()

# load current repository file
set(LOCAL_CURRENT_VERSION_FILE  ${CMAKE_CURRENT_SOURCE_DIR}/../${EXTERNAL_LOCAL_FILENAME})
set(EXTERNAL_LOCAL_CURRENT_FILENAME  local_resource/external_project_local_setting2.config)
if((NOT CFD_TARGET_VERSION) AND (NOT CFD_TARGET_URL) AND (EXISTS ${LOCAL_CURRENT_VERSION_FILE}))
transform_makefile_srclist(${LOCAL_CURRENT_VERSION_FILE} "${CMAKE_CURRENT_BINARY_DIR}/${EXTERNAL_LOCAL_CURRENT_FILENAME}.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/${EXTERNAL_LOCAL_CURRENT_FILENAME}.cmake)
message(STATUS "[external project local] load current cfd-go file")
endif()

# cfd
if(CFD_TARGET_VERSION)
set(CFD_TARGET_TAG  ${CFD_TARGET_VERSION})
message(STATUS "[external project local] cfd target=${CFD_TARGET_VERSION}")
else()
set(CFD_TARGET_TAG  v0.4.8)
endif()
if(CFD_TARGET_URL)
set(CFD_TARGET_REP  ${CFD_TARGET_URL})
message(STATUS "[external project local] cfd url=${CFD_TARGET_URL}")
else()
#set(CFD_TARGET_REP  p2pderivatives/cfd.git)
# TODO: Until p2pderivatives/cfd v0.4.0 is released, have cryptogarageinc referenced.
set(CFD_TARGET_REP  cryptogarageinc/cfd.git)
endif()

if(${USE_GIT_SSH})
set(CFD_URL  git@github.com:${CFD_TARGET_REP})
else()
set(CFD_URL  https://github.com/${CFD_TARGET_REP})
endif()

set(TEMPLATE_PROJECT_NAME           cfd)
set(TEMPLATE_PROJECT_GIT_REPOSITORY ${CFD_URL})
set(TEMPLATE_PROJECT_GIT_TAG        ${CFD_TARGET_TAG})
set(PROJECT_EXTERNAL  "${CMAKE_SOURCE_DIR}/external/${TEMPLATE_PROJECT_NAME}/external")
set(DIR_PATH "${CFD_ROOT_BINARY_DIR}/${TEMPLATE_PROJECT_NAME}")
set(DL_PATH "${CFD_ROOT_BINARY_DIR}/external/${TEMPLATE_PROJECT_NAME}/download")

get_property(PROP_VALUE  GLOBAL  PROPERTY ${TEMPLATE_PROJECT_NAME})
if(PROP_VALUE)
  message(STATUS "[exist directory] ${TEMPLATE_PROJECT_NAME} exist")
else()
configure_file(template_CMakeLists.txt.in ${DL_PATH}/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" -S . -B ${DL_PATH}
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${DL_PATH} )
if(result)
  message(FATAL_ERROR "CMake step for ${TEMPLATE_PROJECT_NAME} failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build ${DL_PATH}
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${DL_PATH} )
if(result)
  message(FATAL_ERROR "Build step for ${TEMPLATE_PROJECT_NAME} failed: ${result}")
endif()
if(EXISTS ${PROJECT_EXTERNAL})
  message(STATUS "[check exist directory] exist ${PROJECT_EXTERNAL}")
  message(STATUS "[check exist directory] dirpath ${DIR_PATH}")
  add_subdirectory(${CMAKE_SOURCE_DIR}/external/${TEMPLATE_PROJECT_NAME}/external
                   ${CFD_ROOT_BINARY_DIR}/external/${TEMPLATE_PROJECT_NAME}/external)
endif()

add_subdirectory(${CMAKE_SOURCE_DIR}/external/${TEMPLATE_PROJECT_NAME}
                 ${DIR_PATH}/build)
set_property(GLOBAL PROPERTY ${TEMPLATE_PROJECT_NAME} 1)
endif()
