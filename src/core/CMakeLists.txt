# setup header only library
unset(headers)
list(APPEND headers
        include/Filters.hpp
        include/MIME.hpp
        include/ReaderWriterLock.hpp
        include/SpinWait.hpp
        include/ThreadAffinity.hpp
        include/ThreadPool.hpp
        include/TimingCtx.hpp
        include/URI.hpp
        include/collection.hpp
        include/opencmw.hpp
)

add_library(core INTERFACE)
target_include_directories(core INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/>)
target_link_libraries(core INTERFACE $<BUILD_INTERFACE:mp-units::mp-units> refl-cpp::refl-cpp utils pthread)
set_target_properties(core PROPERTIES PUBLIC_HEADER "${headers}")

install(
        TARGETS core
        EXPORT opencmwTargets
        PUBLIC_HEADER DESTINATION include/opencmw
)

# setup tests
if(ENABLE_TESTING)
  add_subdirectory(test)
endif()
